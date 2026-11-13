#include "af_xdp_header.h"
#include "aethon/aethon.h"
#include "config/constants.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <openssl/evp.h>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <vector>
#include <filesystem>
#include <array>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <sched.h>
#include <pthread.h>
#include <poll.h>
#include "udp_assembler.h"
#include "ip_address.h"
#include "tcp_pipeline.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <immintrin.h>
#include "main/transport/stun_server.h"
#include "main/net/tap_device.h"
#include "main/dpi/custom_hyperscan_holder.h"
#include "aethon_logger.h"

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <sys/socket.h>
#include <sys/un.h>


// systemd notification protocol implementation

inline void systemd_notify(const char *state){
  const char * socket_path =  getenv("NOTIFY_SOCKET");
  if(!socket_path || !state) return;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return;
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;

  if (socket_path[0] == '@') {
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
  } else {
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  }
  socklen_t len = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path);
  sendto(fd, state, strlen(state), 0, (struct sockaddr *)&addr, len);
  close(fd);

}



// export packet struct


struct alignas(8) AethonStatsExport {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t timestamp_ns;
    uint64_t active_sessions;
    uint64_t speed_pps;
    uint64_t speed_bps;
    uint64_t events[17];
    uint64_t xdp_packets[5]; // 0=ABORTED, 1=DROP, 2=PASS, 3=TX, 4=REDIRECT
    uint64_t xdp_bytes[5];
};



/*
  For IPv4 UDP
  [ Ethernet Header (14B) ][ IPv4 Header (20B) ][ Payload / UDP Header ]
^                        ^                    ^
|                        |                    |
pkt                      pkt + 14             pkt + 14 + iph->ihl*4

*/
namespace aethon {
namespace xdp {

// Global packet and byte counters, aligned on separate 64-byte CPU cachelines
struct alignas(implementation::hardware_destructive_interference_size) CaptureStats {
  alignas(implementation::hardware_destructive_interference_size) std::atomic<uint64_t> total_packets{0};
  alignas(implementation::hardware_destructive_interference_size) std::atomic<uint64_t> total_bytes{0};
  alignas(implementation::hardware_destructive_interference_size) std::atomic<uint64_t> active_sessions{0};
};

inline CaptureStats g_stats;
inline std::atomic<uint64_t> g_worker_active_sessions[64]{};

inline std::atomic<bool> g_running{true};
inline rules::RuleDatabase g_rule_db;
inline scan::HyperscanEngine g_master_scanner;
inline scan::CustomHyperscanHolder g_custom_scanner_holder;

static inline void set_cpu_affinity(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static inline uint16_t get_checksum(const uint8_t *pkt,size_t len){
  uint32_t sum=0;
  while (len >= 2) {
    sum += (static_cast<uint16_t>(pkt[0]) << 8)|static_cast<uint16_t>(pkt[1]);
    pkt += 2;
    len -= 2;
  }

  if (len) sum += static_cast<uint16_t>(pkt[0]) << 8;
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}


// free completion ring
template<typename Config>
static inline void free_completion_ring(aethon_xsk_socket_info *sock, 
                                       std::vector<uint64_t>& tx_pool,
                                       FallbackRing<Config::FALLBACK_CAPACITY>& fallback_ring){
  uint32_t idx = 0;
  while (true) {
    unsigned int completed = xsk_ring_cons__peek(&sock->umen->cq, Config::BATCH_SIZE, &idx);
    if (AETHON_LIKELY(completed == 0)) break;

    // dividing line
    constexpr uint64_t tx_boundary = Config::FQ_RING_SIZE * Config::FRAME_SIZE;

    for(unsigned int i = 0; i < completed; i++){
      uint64_t addr = *xsk_ring_cons__comp_addr(&sock->umen->cq, idx + i);
      if(addr >= tx_boundary){
        // it came from the tx pool
        tx_pool.push_back(addr);
      }else{
        // Reflected RX frame: push to fallback ring so it is safely recycled without drops
        if (AETHON_UNLIKELY(!fallback_ring.push(addr))) {
          uint32_t idx_fq = 0;
          if (xsk_ring_prod__reserve(&sock->umen->fq, 1, &idx_fq) == 1) {
            *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq) = addr;
            xsk_ring_prod__submit(&sock->umen->fq, 1);
          }
        }
      }
    }

    xsk_ring_cons__release(&sock->umen->cq, completed);
  }
}



// Templated worker that accepts any AFXDPEngine configuration
template <typename Engine>
void rx_worker(Engine &engine, int queue_id) {
  using Config = typename Engine::config_type;

  // Pin this worker thread to its dedicated CPU core (skip Core 0 for OS)
  int core_count = std::thread::hardware_concurrency();
  int available_worker_cores = core_count > 1 ? core_count - 1 : 1;
  int target_core = (queue_id % available_worker_cores) + 1; // +1 to skip Core 0
  
  if (core_count == 1) {
      target_core = 0; // Fallback for single-core machines
  }
  
  set_cpu_affinity(target_core);

  auto *sock = engine.get_socket(queue_id);
  if (!sock) {
    std::cerr << "[Queue " << queue_id << "] Error: Invalid socket pointer!\n";
    return;
  }

  int sock_fd = xsk_socket__fd(sock->xsk);
  std::cout << "[Queue " << queue_id << "] Worker started on Core " << target_core << "\n";

  // Ultra-fast stack-allocated ring buffer with capacity defined by template Config
  FallbackRing<Config::FALLBACK_CAPACITY> fallback_ring;

  // Per-worker-thread UDP assembler engine (dedicated Core-pinned instance)
  UDPIpv4Assembler::UDPassemblerEngine assembler;

  IPv4TcpAssembler::TcpAssemblerEngine tcp_assembler;
  auto scanner = g_master_scanner.create_worker();
  uint64_t custom_gen_id = 0;
  scan::HyperscanWorker custom_scanner;
  if (const auto *cg = g_custom_scanner_holder.get()) {
    custom_gen_id = cg->id;
    if (cg->active) {
      custom_scanner = cg->engine.create_worker();
    }
  }
  pipeline::Ja3RateLimiter ja3_limiter;   // per-worker: no sharing, no locks (see tcp_pipeline.h)

  net::TapDevice tap_device;

  tap_device.init(config::net::DEFAULT_TAP_NAME);

  uint32_t idle_iters = 0;
  constexpr uint32_t SPIN_LIMIT = config::net::DEFAULT_SPIN_LIMIT;
  
  std::vector<uint64_t> tx_pool;
  tx_pool.reserve(Config::NUM_FRAMES  - Config::FQ_RING_SIZE);
  for (size_t i = Config::FQ_RING_SIZE; i < Config::NUM_FRAMES; ++i) {
    tx_pool.push_back(i * Config::FRAME_SIZE);
  }

  // Epoll descriptor for non-blocking backend sockets
  int epfd = epoll_create1(EPOLL_CLOEXEC);

  // Monitor BOTH the AF_XDP NIC socket AND backend epoll events so we never sleep when backend has data!
  struct pollfd fds[2];
  fds[0].fd = sock_fd;
  fds[0].events = POLLIN;
  fds[1].fd = epfd;
  fds[1].events = POLLIN;

  while (g_running.load(std::memory_order_relaxed)) {
    if (queue_id < 64) {
      g_worker_active_sessions[queue_id].store(tcp_assembler.session_count(), std::memory_order_relaxed);
    }

    // Lock-free atomic check for custom DPI rule reloads (SIGHUP)
    if (const auto *cg = g_custom_scanner_holder.get(); AETHON_UNLIKELY(cg && cg->id != custom_gen_id)) {
      custom_gen_id = cg->id;
      custom_scanner = cg->active ? cg->engine.create_worker() : scan::HyperscanWorker{};
    }
    
    uint32_t idx_rx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&sock->rx, Config::BATCH_SIZE, &idx_rx);
    free_completion_ring<Config>(sock, tx_pool, fallback_ring);

    uint32_t backend_work = pipeline::drain_backend_events(epfd, sock, tx_pool, tcp_assembler);
    uint32_t rto_work = pipeline::check_tcp_retransmissions(sock, tx_pool, tcp_assembler);
    if (AETHON_UNLIKELY(backend_work > 0 || rto_work > 0)) {
      idle_iters = 0;
      if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->tx))) {
        sendto(sock_fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
      }
      // If we performed active backend I/O and transmitted data to client, continue immediately without sleep!
      if (!rcvd) {
        continue;
      }
    }

    if(AETHON_UNLIKELY(!rcvd)){
      while (!fallback_ring.empty()) {
        uint32_t idx_fq = 0;
        size_t count  = std::min(fallback_ring.size(), static_cast<size_t>(Config::BATCH_SIZE));
        size_t available = xsk_ring_prod__reserve(&sock->umen->fq, count, &idx_fq);
        if(AETHON_UNLIKELY(available == 0)){
          break;
        }

        for(size_t i = 0; i<available;i++){
          *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq + i) = fallback_ring.get(i);
        }
        xsk_ring_prod__submit(&sock->umen->fq, available);
        fallback_ring.advance(available);

      }

      bool has_active = (tcp_assembler.session_count() > 0);
      size_t spin_max = has_active ? 8192 : 64;
      if (idle_iters < spin_max) {
        ++idle_iters;
        #if defined (__x86_64)
        _mm_pause();
        #endif
        continue;
      }

      if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->umen->fq))) {
        recvfrom(sock_fd, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
      }

      // Traffic has stalled. Run the session reaper on a 1s timer (self-gated) so idle and
      // TIME_WAIT sessions still drain with no packets arriving — otherwise session_count stays
      // > 0, the worker keeps busy-polling, and leftover flows never disappear after a load test.
      {
        uint64_t idle_now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        tcp_assembler.reap_if_due(idle_now_ns);
      }

      // If active sessions exist, perform non-blocking poll (timeout 0) to avoid artificial millisecond latency!
      // If truly idle with 0 active connections, sleep briefly in poll (1ms) to save CPU.
      poll(fds, 2, has_active ? 0 : 1);
      continue;
    }

    idle_iters = 0;

    uint64_t batch_bytes = 0;
    for (unsigned int i = 0; i < rcvd; ++i) {
      // Software prefetch the next descriptor ahead into CPU L1 cache
      if (i + 4 < rcvd) {
        AETHON_BUILTIN_PREFETCH(xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i + 4), 0, 1);
      }
      const auto *__restrict__ desc = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i);

      /* PACKET PROCESSING LOGIC */
      uint8_t *__restrict__ pkt = reinterpret_cast<uint8_t *>(
          xsk_umem__get_data(sock->umen->buffer, desc->addr));
      const auto *__restrict__ eth = reinterpret_cast<const struct ether_header *>(pkt);
      size_t l3_offset = sizeof(struct ether_header);
      uint16_t eth_type = ntohs(eth->ether_type);

      // Handle 802.1Q and 802.1ad (QinQ) VLAN tags
      while ((eth_type == 0x8100 || eth_type == 0x88A8) && l3_offset + 4 <= desc->len) {
        eth_type = ntohs(*reinterpret_cast<const uint16_t *>(pkt + l3_offset + 2));
        l3_offset += 4;
      }

      if (AETHON_LIKELY(eth_type == ETHERTYPE_IP)) {
        if (AETHON_LIKELY(desc->len >= l3_offset + sizeof(struct iphdr))) {
          auto *__restrict__ iph = reinterpret_cast<struct iphdr *>(pkt + l3_offset);

          // Validate IPv4 checksum (reject corrupted or checksum-evasion packets)
          if (AETHON_UNLIKELY(!Ipv4::is_valid_ipv4_checksum(iph))) {
            goto recycle_slot;
          }

          const size_t ip_hdr_len = iph->ihl * 4;
          const size_t ip_total_len = ntohs(iph->tot_len);
          if (AETHON_UNLIKELY(ip_hdr_len < sizeof(struct iphdr) || ip_total_len < ip_hdr_len ||
                              ip_total_len > desc->len - l3_offset)) {
            goto recycle_slot;
          }

          // Host IP filter: Accept traffic for our interface private IPs, broadcast, or multicast
          const uint32_t dst_ip = iph->daddr;
          const bool is_for_this_host = (Ipv4::g_host_ips.count == 0) ||
                                        Ipv4::g_host_ips.contains(dst_ip) ||
                                        (dst_ip == INADDR_BROADCAST) ||
                                        (IN_MULTICAST(ntohl(dst_ip)));

          if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(is_for_this_host && iph->protocol == IPPROTO_UDP, 1, 0.15)) {
            uint16_t frag_field = ntohs(iph->frag_off);
            bool more_fragments = (frag_field & IP_MF) != 0;
            uint16_t frag_offset = (frag_field & IP_OFFMASK) * 8;
            
            size_t ip_hdr_len = iph->ihl * 4;
            const uint8_t *__restrict__ frag_payload = reinterpret_cast<const uint8_t *>(iph) + ip_hdr_len;
            uint16_t frag_len = ntohs(iph->tot_len) - ip_hdr_len;

            // 99.5% of packets are unfragmented (expect 1 with 0.995 probability)
            if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY((!more_fragments && frag_offset == 0), 1, 0.995)) {
              if (AETHON_LIKELY(frag_len >= sizeof(struct udphdr))) {
                const auto *__restrict__ udph = reinterpret_cast<const struct udphdr *>(frag_payload);
                const uint8_t *__restrict__ udp_app_payload = frag_payload + sizeof(struct udphdr);
                size_t udp_app_len = frag_len - sizeof(struct udphdr);

                // 1. STUN Server Fast Reflection on Port 3478
                if (AETHON_UNLIKELY(ntohs(udph->dest) == stun::StunServer::DEFAULT_PORT)) {
                  if (stun::StunServer::is_binding_request(udp_app_payload, udp_app_len)) {
                    uint8_t stun_resp[stun::StunServer::RESPONSE_SIZE];
                    size_t resp_len = stun::StunServer::build_response(
                        udp_app_payload, udp_app_len, iph->saddr, udph->source, stun_resp, sizeof(stun_resp));
                    if (resp_len > 0) {
                      bool sent = net::PacketInjector::ipv4_send_udp_reply(
                          sock, desc->addr, pkt, eth, iph, udph, stun_resp, resp_len);
                      if (sent) {
                        continue; // Buffer forwarded to TX ring; completion ring will recycle it
                      }
                    }
                  }
                  goto recycle_slot;
                }

                // 2. All other UDP ports: Hyperscan DPI inspection
                if (AETHON_LIKELY(udp_app_len > 0)) {
                  bool is_blocked = scanner.scan(udp_app_payload, udp_app_len) ||
                                    (AETHON_UNLIKELY(custom_scanner.is_ready()) &&
                                     custom_scanner.scan(udp_app_payload, udp_app_len));
                  if (AETHON_UNLIKELY(is_blocked)) {
                    std::cout << "\n[IPS BLOCK] ATTACK DETECTED: Malicious UDP Payload Dropped!" << std::endl;
                    stats::count(stats::Event::RstDpiMatch);
                    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &iph->saddr, s_ip, sizeof(s_ip));
                    inet_ntop(AF_INET, &iph->daddr, d_ip, sizeof(d_ip));
                    aethon::log::log_event("CRITICAL", "UDP_IDS", "DPI_ATTACK_DETECTED",
                                           s_ip, ntohs(udph->source),
                                           d_ip, ntohs(udph->dest),
                                           "UDP", "DROP", "ATTACK DETECTED: Malicious UDP exploit payload intercepted & dropped by DPI");
                    goto recycle_slot;
                  }
                }

                // Forward clean, verified UDP frame to host Linux kernel via TAP!
                tap_device.write_frame(pkt, desc->len);
              }
            } else {
              // Fragmented Packet Path
              UDPIpv4Assembler::FragmentKey key;
              key.src_ip   = iph->saddr;
              key.dst_ip   = iph->daddr;
              key.ip_id    = ntohs(iph->id);
              key.protocol = iph->protocol;

              uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::steady_clock::now().time_since_epoch()).count();

              UDPIpv4Assembler::AssemblyResult res = assembler.process_fragment(
                  key, frag_offset, frag_payload, frag_len, more_fragments, now_ns);

              if (AETHON_UNLIKELY(res.is_complete)) {
                // Reassembled Datagram: Full payload available for Hyperscan scanning
                if (AETHON_LIKELY(res.payload_len > 0)) {
                  bool is_blocked = scanner.scan(res.payload, res.payload_len) ||
                                    (AETHON_UNLIKELY(custom_scanner.is_ready()) &&
                                     custom_scanner.scan(res.payload, res.payload_len));
                  if (AETHON_UNLIKELY(is_blocked)) {
                    std::cout << "\n[IPS BLOCK] ATTACK DETECTED: Malicious Fragmented UDP Datagram Dropped!" << std::endl;
                    stats::count(stats::Event::RstDpiMatch);
                    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &iph->saddr, s_ip, sizeof(s_ip));
                    inet_ntop(AF_INET, &iph->daddr, d_ip, sizeof(d_ip));
                    aethon::log::log_event("CRITICAL", "UDP_IDS", "DPI_ATTACK_DETECTED",
                                           s_ip, 0,
                                           d_ip, 0,
                                           "UDP", "DROP", "ATTACK DETECTED: Malicious fragmented UDP datagram intercepted & dropped by DPI");
                    assembler.release_completed(res);
                    goto recycle_slot;
                  }
                }

                tap_device.write_frame(pkt, desc->len);
                assembler.release_completed(res);
              }
            }
          } else if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(is_for_this_host && iph->protocol == IPPROTO_TCP, 1, 0.85)) {
            const size_t ip_total_len = ntohs(iph->tot_len);
            uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();

            bool is_blocked = pipeline::handle_tcp_packet(
                sock, desc->addr, pkt, eth, iph, ip_total_len, now_ns, tcp_assembler,
                scanner, tx_pool, epfd, ja3_limiter, custom_scanner, custom_gen_id);
            if (AETHON_UNLIKELY(is_blocked)) {
              continue;
            }
          } else if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(is_for_this_host && iph->protocol == IPPROTO_ICMP, 1, 0.01)) {
            const size_t ip_hdr_len=iph->ihl*4;
            if (AETHON_UNLIKELY(ip_hdr_len<sizeof(struct iphdr))) goto recycle_slot;
            const size_t ip_total_len=ntohs(iph->tot_len);

            if (ip_total_len<ip_hdr_len+sizeof(struct icmphdr)) goto recycle_slot;
            if (AETHON_UNLIKELY(ip_total_len > desc->len - l3_offset)) goto recycle_slot;
            if (AETHON_UNLIKELY(iph->ihl < 5)) goto recycle_slot;

            auto* __restrict__ icmph=reinterpret_cast<struct icmphdr*>(reinterpret_cast<uint8_t*>(iph)+ip_hdr_len);
            if (AETHON_LIKELY(icmph->type==ICMP_ECHO && icmph->code==0)){
              auto* __restrict__ icmp_eth=reinterpret_cast<struct ether_header*>(pkt);
              auto* __restrict__ icmp_iph=reinterpret_cast<struct iphdr*>(pkt + l3_offset);

              uint8_t temp_mac[ETH_ALEN];
              memcpy(temp_mac,icmp_eth->ether_shost,ETH_ALEN);
              memcpy(icmp_eth->ether_shost,icmp_eth->ether_dhost,ETH_ALEN);
              memcpy(icmp_eth->ether_dhost,temp_mac,ETH_ALEN);

              std::swap(icmp_iph->saddr,icmp_iph->daddr);
              icmph->type=ICMP_ECHOREPLY;
              icmph->checksum=0;
              icmph->checksum=htons(get_checksum(reinterpret_cast<const uint8_t*>(icmph),ip_total_len-ip_hdr_len));
              icmp_iph->check=0;
              icmp_iph->check=htons(get_checksum(reinterpret_cast<uint8_t*>(icmp_iph),ip_hdr_len));

              uint32_t idx;
              if (AETHON_UNLIKELY(xsk_ring_prod__reserve(&sock->tx,1,&idx)!=1)) goto recycle_slot;
              struct xdp_desc* tx_desc=xsk_ring_prod__tx_desc(&sock->tx,idx);
              tx_desc->addr=desc->addr;
              tx_desc->len=desc->len;

              xsk_ring_prod__submit(&sock->tx,1);
              if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->tx))) {
                sendto(sock_fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
              }
              continue;
            } else if (icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_FRAG_NEEDED) {
              // Path MTU Discovery (PMTU, RFC 1191):
              // Payload contains the quoted original IPv4 header + TCP header
              const uint8_t *payload = reinterpret_cast<const uint8_t*>(icmph) + sizeof(struct icmphdr);
              if (ip_total_len >= ip_hdr_len + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8) {
                const auto *orig_iph = reinterpret_cast<const struct iphdr*>(payload);
                size_t orig_ip_hlen = orig_iph->ihl * 4;
                if (orig_ip_hlen >= sizeof(struct iphdr) &&
                    ip_total_len >= ip_hdr_len + sizeof(struct icmphdr) + orig_ip_hlen + 8) {
                  if (orig_iph->protocol == IPPROTO_TCP) {
                    const auto *orig_tcph = reinterpret_cast<const struct tcphdr*>(payload + orig_ip_hlen);
                    uint16_t next_mtu = ntohs(icmph->un.frag.mtu);
                    tcp_assembler.handle_icmp_pmtu(
                        orig_iph->daddr, orig_tcph->dest,
                        orig_iph->saddr, orig_tcph->source,
                        next_mtu);
                  }
                }
              }
              // Forward PMTU notification to host Linux kernel via TAP
              tap_device.write_frame(pkt, desc->len);
              aethon::stats::count(aethon::stats::Event::IcmpForwardedToKernel);
              goto recycle_slot;
            } else {
              // Forward all other ICMP types (Time Exceeded, other Unreachables, etc.)
              // to the host Linux kernel via TAP interface (aethon0)!
              tap_device.write_frame(pkt, desc->len);
              aethon::stats::count(aethon::stats::Event::IcmpForwardedToKernel);
              goto recycle_slot;
            }
          }
        }
      }

recycle_slot:
      batch_bytes += desc->len;
      if (AETHON_UNLIKELY(!fallback_ring.push(desc->addr))) {
        uint32_t idx_fq = 0;
        if (xsk_ring_prod__reserve(&sock->umen->fq, 1, &idx_fq) == 1) {
          *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq) = desc->addr;
          xsk_ring_prod__submit(&sock->umen->fq, 1);
        }
      }
    }

    // Update atomic counters (relaxed ordering for low contention)
    g_stats.total_packets.fetch_add(rcvd, std::memory_order_relaxed);
    g_stats.total_bytes.fetch_add(batch_bytes, std::memory_order_relaxed);

    // Release the consumed descriptors in the RX ring
    xsk_ring_cons__release(&sock->rx, rcvd);

    while (!fallback_ring.empty()) {
      uint32_t idx_fq = 0;
      size_t count = std::min(fallback_ring.size(), static_cast<size_t>(Config::BATCH_SIZE));
      size_t available = xsk_ring_prod__reserve(&sock->umen->fq, count, &idx_fq);
      if (AETHON_UNLIKELY(available == 0)) {
        break;
      }
      for (size_t i = 0; i < available; ++i) {
        *xsk_ring_prod__fill_addr(&sock->umen->fq, idx_fq + i) = fallback_ring.get(i);
      }
      xsk_ring_prod__submit(&sock->umen->fq, available);
      fallback_ring.advance(available);
    }

    if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->umen->fq))) {
      recvfrom(sock_fd, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
    }
  }

  if (queue_id < 64) {
    g_worker_active_sessions[queue_id].store(0, std::memory_order_relaxed);
  }
}

static std::atomic<bool> g_reload_requested{false};
static std::atomic<int> g_services_map_fd{-1};
static std::atomic<int> g_mode_map_fd{-1};
static std::atomic<int> g_xdp_stats_map_fd{-1};

inline void stats_printer() {
  // Pin telemetry thread strictly to Core 0 (alongside Linux OS & IRQs)
  // so packet workers on Cores 1+ have 100% uninterrupted CPU time
  set_cpu_affinity(config::system::TELEMETRY_CPU_CORE);

  uint64_t last_packets = 0;
  uint64_t last_bytes = 0;

  while (g_running.load(std::memory_order_relaxed)) {



    std::this_thread::sleep_for(std::chrono::seconds(config::system::WATCHDOG_INTERVAL_SEC));
    systemd_notify("WATCHDOG=1");

    // Sync match_only engine mode from eBPF map (0 = Bypass, 1 = Match-Only, 2 = Full Protection)
    int mode_fd = g_mode_map_fd.load(std::memory_order_relaxed);
    if (mode_fd >= 0) {
      uint32_t key = 0, val = 2;
      if (bpf_map_lookup_elem(mode_fd, &key, &val) == 0) {
        aethon::pipeline::g_engine_mode.store(val, std::memory_order_relaxed);
      }
    }





    // Zero-Downtime Hot Reload triggered by SIGHUP (systemctl reload aethon)
    if (AETHON_UNLIKELY(g_reload_requested.exchange(false, std::memory_order_relaxed))) {
      std::cout << "\n[Config] SIGHUP received: Executing zero-downtime hot reload...\n";
      const char *conf = std::filesystem::exists("rules/services.conf") ? "rules/services.conf"
                       : std::filesystem::exists("../../rules/services.conf") ? "../../rules/services.conf" : nullptr;
      if (conf) {
        size_t loaded = aethon::pipeline::g_service_registry.load_from_file(conf);
        if (loaded > 0) {
          std::cout << "[Config] Reloaded " << loaded << " services into Service Registry without downtime.\n";
          int map_fd = g_services_map_fd.load(std::memory_order_relaxed);
          if (map_fd >= 0) {
            auto ports = aethon::pipeline::g_service_registry.get_listening_ports();
            for (uint16_t port : ports) {
              uint8_t val = 1;
              bpf_map_update_elem(map_fd, &port, &val, BPF_ANY);
              std::cout << "[Config] Synced port " << port << " to eBPF filter\n";
            }
          }
        }
      }
      const char *dom_file = std::filesystem::exists("rules/blocked_domains.txt") ? "rules/blocked_domains.txt"
                           : std::filesystem::exists("../../rules/blocked_domains.txt") ? "../../rules/blocked_domains.txt" : nullptr;
      if (dom_file) {
        size_t doms = aethon::pipeline::g_domain_blocklist.load_from_file(dom_file);
        std::cout << "[Config] Reloaded " << doms << " blocked domains into TLS SNI blocklist.\n";
      }
      const char *custom_file = std::filesystem::exists("rules/custom_rules.rules") ? "rules/custom_rules.rules"
                              : std::filesystem::exists("../../rules/custom_rules.rules") ? "../../rules/custom_rules.rules" : nullptr;
      if (custom_file) {
        aethon::scan::CompileStats cs;
        if (g_custom_scanner_holder.reload_from_file(custom_file, &cs)) {
          std::cout << "[Config] Reloaded " << cs.compiled << " custom DPI rules ("
                    << cs.blocking << " blocking) in " << static_cast<int>(cs.compile_ms) << " ms.\n";
        }
      }
      std::fflush(stdout);
    }
    uint64_t current_packets = g_stats.total_packets.load(std::memory_order_relaxed);
    uint64_t current_bytes = g_stats.total_bytes.load(std::memory_order_relaxed);

    AethonStatsExport export_data{};

    // Read real XDP action counters from eBPF percpu map
    int xdp_fd = g_xdp_stats_map_fd.load(std::memory_order_relaxed);
    if (xdp_fd >= 0) {
      static int ncpus = libbpf_num_possible_cpus();
      if (ncpus <= 0) ncpus = 1;
      std::vector<struct datarec> percpu_vals(ncpus);
      for (uint32_t act = 0; act < 5; ++act) {
        if (bpf_map_lookup_elem(xdp_fd, &act, percpu_vals.data()) == 0) {
          uint64_t sum_p = 0, sum_b = 0;
          for (int c = 0; c < ncpus; ++c) {
            sum_p += percpu_vals[c].rx_packets;
            sum_b += percpu_vals[c].rx_bytes;
          }
          export_data.xdp_packets[act] = sum_p;
          export_data.xdp_bytes[act] = sum_b;
        }
      }
      uint64_t xdp_total_p = export_data.xdp_packets[4] + export_data.xdp_packets[2];
      uint64_t xdp_total_b = export_data.xdp_bytes[4] + export_data.xdp_bytes[2];
      if (xdp_total_p > current_packets) current_packets = xdp_total_p;
      if (xdp_total_b > current_bytes) current_bytes = xdp_total_b;
    }

    uint64_t pps = (current_packets >= last_packets) ? (current_packets - last_packets) : 0;
    uint64_t bps = (current_bytes >= last_bytes) ? (current_bytes - last_bytes) : 0;

    double mbps = (bps * 8.0) / 1000000.0; // Megabits per second

    export_data.total_packets = current_packets;
    export_data.total_bytes = current_bytes;
    export_data.speed_pps = pps;
    export_data.speed_bps = bps;

    std::cout << "\r[Stats] Speed: " << pps << " pps | " 
              << std::fixed << std::setprecision(2) << mbps << " Mbps | Total: "
              << current_packets << " pkts" << std::flush;

    last_packets = current_packets;
    last_bytes = current_bytes;

    // Every 5 s, if any reset/drop counter changed, print them on their own line
    static uint64_t tick = 0, last_events = 0;
    if (++tick % 5 == 0) {
      uint64_t events = aethon::stats::total();
      if (events != last_events) {
        std::cout << std::endl;
        aethon::stats::print_nonzero(stdout, "[Events]");
        std::fflush(stdout);
        last_events = events;
      }
#if defined(__GLIBC__)
      // Return memory freed by closed sessions (reassembly rings, TLS buffers) to the OS.
      malloc_trim(0);
#endif
    }

    export_data.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
    std::chrono::steady_clock::now().time_since_epoch()).count();

    uint64_t total_active = 0;
    for (int q = 0; q < 64; ++q) {
      total_active += g_worker_active_sessions[q].load(std::memory_order_relaxed);
    }
    g_stats.active_sessions.store(total_active, std::memory_order_relaxed);
    export_data.active_sessions = total_active;
    for (size_t i = 0; i < 17; ++i) {
        export_data.events[i] = aethon::stats::g_events[i].load(std::memory_order_relaxed);
    }

    // write to the /dev/shm/aethon_stats.shm
    int fd = ::open("/dev/shm/aethon_stats.shm", O_CREAT | O_RDWR, 0666);
    if (fd >= 0) {
        ssize_t ret = ::pwrite(fd, &export_data, sizeof(export_data), 0);
        (void)ret;
        ::close(fd);
    }

  }
}

using ActiveEngine = DefaultEngine;


template <typename Engine>
void pin_xdp_map([[maybe_unused]] Engine& engine, struct bpf_map* map, const char* name) {
    if (!map) {
        std::cerr << "\nNo XDP map provided\n";
        return;
    }
    constexpr const char* pin_dir = config::net::DEFAULT_BPF_PIN_DIR;
    if (mkdir(pin_dir, 0755) != 0 && errno != EEXIST) {
        perror("Failed to create BPF pin directory");
        return;
    }
    if (bpf_map__is_pinned(map)) {
        return; // Already pinned and reused
    }
    std::string pin_path = std::string(pin_dir) + "/" + name;
    int err = bpf_map__pin(map, pin_path.c_str());
    if (err == -EEXIST) {
        unlink(pin_path.c_str());
        err = bpf_map__pin(map, pin_path.c_str());
    }
    if (err == 0) {
        std::cout << "[Engine] Map '" << name << "' pinned successfully\n";
    } else {
        std::cerr << "[Engine] Failed to pin map '" << name << "': " << err << '\n';
    }
}

// DefaultEngine uses XdpConfig with 4096 frames (8MB UMEM), 2048 ring sizes, 64 batch.
// You can define custom configs here if needed.

static void sig_handler(int) {
  g_running.store(false, std::memory_order_relaxed);
}

static void sighup_handler(int) {
  g_reload_requested.store(true, std::memory_order_relaxed);
}

} // namespace xdp
} // namespace aethon

#include <csignal>

int main(int argc, char **argv) {
  using namespace aethon::xdp;

  // Initialize FluxIO kernel-bypass asynchronous security logger
  aethon::log::init_logger("logs/aethon_security.jsonl");

  std::signal(SIGINT, sig_handler);
  std::signal(SIGTERM, sig_handler);
  std::signal(SIGHUP, sighup_handler);

  const char *ifname = "veth0";
  const char *prog_path = "src/main/ebpf/xdp_kern_prog.o";

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "-i") == 0 || std::strcmp(argv[i], "--interface") == 0) {
      if (i + 1 < argc) ifname = argv[++i];
    } else if (std::strcmp(argv[i], "-p") == 0 || std::strcmp(argv[i], "--prog") == 0) {
      if (i + 1 < argc) prog_path = argv[++i];
    } else if (std::strcmp(argv[i], "--skb") == 0 || std::strcmp(argv[i], "-s") == 0) {
      // Recognized flag for generic XDP mode
      continue;
    } else if (argv[i][0] != '-') {
      // Positional argument
      static int pos = 0;
      if (pos == 0) ifname = argv[i];
      else if (pos == 1) prog_path = argv[i];
      pos++;
    }
  }

  // Discover and cache all local IPv4 addresses on this interface (AWS private IPs)
  aethon::Ipv4::load_interface_ips(ifname);

  // Rule sets: rules/rulesets.conf lists files and how matches are handled (block / policy / alert).
  // Without it, fall back to the single local rule file where every match blocks.
  const char *conf = std::filesystem::exists("rules/rulesets.conf") ? "rules/rulesets.conf"
                   : std::filesystem::exists("../../rules/rulesets.conf") ? "../../rules/rulesets.conf" : nullptr;
  if (conf) {
    std::cout << "Loading rule sets from " << conf << ":\n";
    auto st = g_rule_db.load_rulesets(conf);
    std::cout << "Rules: parsed " << st.parsed << ", loaded " << st.loaded << " (" << st.blocking
              << " blocking), skipped " << st.skipped_outbound << " outbound/response, "
              << st.skipped_unsupported << " with unsupported conditions, " << st.skipped_protocol
              << " non-TCP\n";
  } else {
    size_t total_rules = g_rule_db.load_from_file("rules/test_rules.rules");
    if (total_rules == 0) {
      total_rules = g_rule_db.load_from_file("../../rules/test_rules.rules");
    }
    std::cout << "Loaded " << total_rules << " Snort/Suricata rules from test_rules.rules.\n";
  }
  if (!g_rule_db.empty()) {
    g_master_scanner.set_alert_callback([](const aethon::scan::AttackAlert &alert) {
      // Print the first few hits per SID only: informational rules can fire on every request,
      // and printing runs on the packet thread
      static std::array<std::atomic<uint32_t>, 4096> seen{};
      const uint32_t n = seen[alert.sid % seen.size()].fetch_add(1, std::memory_order_relaxed);
      if (n >= 3) return;
      std::cout << "\n[" << (alert.blocking ? "ALERT" : "LOG") << "] SID: " << alert.sid;
      if (alert.rule) {
        std::cout << " | Msg: " << alert.rule->msg;
      }
      if (n == 2) std::cout << " (further hits of this SID not printed)";
      std::cout << std::endl;
    });
    aethon::scan::CompileStats cs;
    const char *cache_dir = std::filesystem::exists("rules") ? "rules/.hs_cache" : "../../rules/.hs_cache";
    if (g_master_scanner.compile_or_load(g_rule_db, cache_dir, cs)) {
      std::cout << "Hyperscan: " << (cs.from_cache ? "loaded " : "compiled ") << cs.compiled
                << " patterns (" << cs.blocking << " blocking) in " << static_cast<int>(cs.compile_ms)
                << " ms" << (cs.from_cache ? " from cache" : "") << "; skipped " << cs.skipped_invalid
                << " unsupported regex, " << cs.skipped_weak << " too short; database "
                << cs.database_bytes / 1024 << " KB, stream state " << cs.stream_state_bytes << " B/connection\n";
    } else {
      std::cerr << "Hyperscan: compile FAILED, deep packet inspection is disabled\n";
    }
  }

  g_custom_scanner_holder.set_alert_callback([](const aethon::scan::AttackAlert &alert) {
    std::cout << "\n[CUSTOM DPI " << (alert.blocking ? "BLOCK" : "AUDIT") << "] SID: " << alert.sid;
    if (alert.rule) {
      std::cout << " | Msg: " << alert.rule->msg;
    }
    std::cout << std::endl;
    if (!alert.blocking) {
      std::string msg = "Custom DPI audit match (SID " + std::to_string(alert.sid) + ")";
      if (alert.rule && !alert.rule->msg.empty()) {
        msg += ": " + alert.rule->msg;
      }
      aethon::log::log_event("ALERT", "DPI", "CUSTOM_RULE_AUDIT",
                             "0.0.0.0", 0, "0.0.0.0", 0, "TCP", "AUDIT", msg.c_str());
    }
  });
  const char *custom_rules_path = std::filesystem::exists("rules/custom_rules.rules") ? "rules/custom_rules.rules"
                                : std::filesystem::exists("../../rules/custom_rules.rules") ? "../../rules/custom_rules.rules" : nullptr;
  if (custom_rules_path) {
    aethon::scan::CompileStats custom_cs;
    if (g_custom_scanner_holder.reload_from_file(custom_rules_path, &custom_cs)) {
      std::cout << "Custom DPI: compiled " << custom_cs.compiled << " rules (" << custom_cs.blocking
                << " blocking) from " << custom_rules_path << " in " << static_cast<int>(custom_cs.compile_ms) << " ms\n";
    }
  }


  size_t total_domains = aethon::pipeline::g_domain_blocklist.load_from_file("rules/blocked_domains.txt");
  if (total_domains == 0) {
    total_domains = aethon::pipeline::g_domain_blocklist.load_from_file("../../rules/blocked_domains.txt");
  }
  std::cout << "Loaded " << total_domains << " blocked domains into TLS SNI blocklist.\n";



  // setup the SSL and TLS
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  size_t total_services = aethon::pipeline::g_service_registry.load_from_file("rules/services.conf");
  if(total_services == 0){
    total_services = aethon::pipeline::g_service_registry.load_from_file("../../rules/services.conf");
  }

   std::cout << "Loaded " << total_services << " TLS services into Service Registry.\n";

  

  std::cout << "Starting AF_XDP on interface: " << ifname << "\n";
  std::cout << "Using eBPF Program: " << prog_path << "\n";

  ActiveEngine engine;
  if (!engine.setup(ifname, prog_path, "aethon_xdp_prog_main",
                    XDP_MODE_SKB, "aethon_xsks_map", "queue_config_map")) {
    std::cerr << "Failed to initialize AF_XDP engine.\n";
    return 1;
  }

  int num_queues = engine.active_queues();
  std::cout << "Running on " << num_queues << " queues...\n";

  pin_xdp_map(engine, engine.find_map("aethon_ip_blocklist"), "aethon_ip_blocklist");
  pin_xdp_map(engine, engine.find_map("aethon_rate_limiter"), "aethon_rate_limiter");
  pin_xdp_map(engine, engine.find_map("rate_limiter_params"), "rate_limiter_params");
  pin_xdp_map(engine, engine.find_map("aethon_firewall_map"), "aethon_firewall_map");

  struct bpf_map *xdp_stats_map = engine.find_map("aethon_xdp_stats_map");
  if (xdp_stats_map) {
    pin_xdp_map(engine, xdp_stats_map, "aethon_xdp_stats_map");
    int xdp_fd = bpf_map__fd(xdp_stats_map);
    if (xdp_fd >= 0) {
      g_xdp_stats_map_fd.store(xdp_fd, std::memory_order_relaxed);
    }
  }

  // Pin and initialize match_only mode map (0 = Bypass, 1 = Match-only, 2 = Full Protection)
  struct bpf_map *mode_map = engine.find_map("match_only");
  if (mode_map) {
    pin_xdp_map(engine, mode_map, "match_only");
    int mode_fd = bpf_map__fd(mode_map);
    if (mode_fd >= 0) {
      g_mode_map_fd.store(mode_fd, std::memory_order_relaxed);
      uint32_t key = 0;
      uint32_t val = 2; // Default = 2 (Full Protection)
      const char *mode_file = std::filesystem::exists("rules/engine_mode.json") ? "rules/engine_mode.json"
                            : std::filesystem::exists("../../rules/engine_mode.json") ? "../../rules/engine_mode.json" : nullptr;
      if (mode_file) {
        std::ifstream mf(mode_file);
        std::string line;
        while (std::getline(mf, line)) {
          size_t p = line.find("\"mode\":");
          if (p != std::string::npos) {
            try {
              int m = std::stoi(line.substr(p + 7));
              if (m >= 0 && m <= 2) val = static_cast<uint32_t>(m);
            } catch (...) {}
          }
        }
      }
      bpf_map_update_elem(mode_fd, &key, &val, BPF_ANY);
      aethon::pipeline::g_engine_mode.store(val, std::memory_order_relaxed);
      std::cout << "[Engine] Initialized match_only map (mode = " << val << ": "
                << (val == 0 ? "Bypass" : val == 1 ? "Match-Only" : "Full Protection") << ")\n";
    }
  }

  // Issue #4: Pin and populate aethon_services_map with active ports from services.conf
  struct bpf_map *services_map = engine.find_map("aethon_services_map");
  if (services_map) {
    pin_xdp_map(engine, services_map, "aethon_services_map");
    int map_fd = bpf_map__fd(services_map);
    if (map_fd >= 0) {
      g_services_map_fd.store(map_fd, std::memory_order_relaxed);
      auto ports = aethon::pipeline::g_service_registry.get_listening_ports();
      for (uint16_t port : ports) {
        uint8_t val = 1;
        bpf_map_update_elem(map_fd, &port, &val, BPF_ANY);
        std::cout << "[Engine] Registered service port " << port << " in eBPF XDP filter\n";
      }
    }
  }


   // Notify systemd that initialization is complete and we are ready for traffic
  systemd_notify("READY=1");

  // writing to the shared memory for the golang

  int pid_fd = ::open("/dev/shm/aethon.pid", O_CREAT | O_WRONLY | O_TRUNC, 0666);
  if (pid_fd >= 0) {
    std::string pid_str = std::to_string(getpid()) + "\n";
    ssize_t ret = ::write(pid_fd, pid_str.c_str(), pid_str.size());
    (void)ret;
    ::close(pid_fd);
  }


  std::vector<std::thread> workers;
  
  workers.emplace_back(stats_printer);

  for (int q = 0; q < num_queues; ++q) {
    workers.emplace_back(rx_worker<ActiveEngine>, std::ref(engine), q);
  }

  for (auto &w : workers) {
    w.join();
  }
  std::cout << "\n[Engine] Gracefully stopped all workers.\n" << std::flush;
  if (!aethon::stats::print_nonzero(stdout, "[Events] totals:")) {
    std::cout << "[Events] totals: none\n";
  }

   aethon::log::shutdown_logger();
   systemd_notify("STOPPING=1");
  return 0;
}
