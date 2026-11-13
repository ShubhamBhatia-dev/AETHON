/*

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  (16 bits each)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |  (32 bits!)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |  (32 bits!)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |  (16 bits)
| (4b)  |   (6b)    |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    | (0-40 bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


tcp->doff ---> the length of the Tcp header in 4-byte words.

flags 6 bits

SYN --> starts a new connection (Used to create a session)
ACK ---> acknodeges received data
FIN --> sender has finished sending data (graceful close)
RST  --> Abruptly kills the connection immediately (purge session)

TCP session key = (source_ip , destination_ip, source_port, destination_port)

TCP handshake

      CLIENT                                  SERVER
         |                                       |
         | ---- 1. SYN (seq = 1000) -----------> |  (Client wants to connect)
         |                                       |
         | <--- 2. SYN-ACK (seq=5000, ack=1001)- |  (Server accepts)
         |                                       |
         | ---- 3. ACK (seq = 1001, ack=5001)--> |  (Connection ESTABLISHED!)
         |                                       |
         | ---- 4. DATA (seq = 1001, len=500)--> |  (Actual HTTP/TLS payload!)


A SYN flag virtually consue 1 sequence number
that means the very first real byte of connection will start at : INtital Data sequence Number (ISN) = SYN_seq + 1

MSS (maximum segment size ) -> Options Kind = 2 ---> tell the other side the mtu is 1500 bytes. subtract 40 byttes for I{/Tcp header, the maximum payload i can receive in 1 pakcket is 1460 bytes;
Window  Scale ( option 3) --> header_window << shift 

3. SACK Permitted (Selective Acknowledgment) — Option Kind = 4
In basic TCP, if Packet 2 is lost but Packets 3, 4, 5 arrive, the server has to ask for everything starting from 2 again.
With SACK, the receiver can say: "I got bytes 3000..5000, just retransmit bytes 1000..2999."

------  TCP option use standard TLV (type length value ) encoding
+------------+------------+-----------------------+
| Kind (1B)  | Length (1B)| Value (Length-2 Bytes)|
+------------+------------+-----------------------+

Kind = 0 (TCPOPT_EOL): End of options list. Stop parsing immediately!
Kind = 1 (TCPOPT_NOP): No-operation (1 byte of padding for alignment). Skip 1 byte.

*/

/*

SACK OPTION WIRED FORM

 Byte 0       Byte 1       Byte 2..5         Byte 6..9         Byte 10..13       Byte 14..17
+-----------+------------+-----------------+-----------------+-----------------+-----------------+
| Kind = 5  | Length = L | Left Edge 1     | Right Edge 1    | Left Edge 2     | Right Edge 2    |
| (1 byte)  | (1 byte)   | (4 bytes)       | (4 bytes)       | (4 bytes)       | (4 bytes)       |
+-----------+------------+-----------------+-----------------+-----------------+-----------------+
                         |<------ 1st SACK Block ------->| |<------ 2nd SACK Block ------->|
                         |<------------------------ 8 bytes ------------------------------>|

*/
#pragma once
#include <hs/hs.h>
#include <vector>
#include "aethon/aethon.h"
#include "config/constants.h"
#include "tcp_congestion.h"
#include "event_counters.h"
#include "udp_assembler.h"
#include <random>

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif

#include "aethon/single_thread_hasmap.h"
#include "allocator/slab_allocator.h"
#include "tls_engine.h"
#include <array>
#include <cstddef>

#include <cstdint>
#include <cstring>
#include <linux/in.h>
#include <new>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include "allocator/memory_budget.h"

namespace aethon {
    namespace IPv4TcpAssembler {
        enum class TcpState : uint8_t{
            CLOSED = 0,
            SYN_SENT = 1, // SAW SYN FROM THE CLIEND
            ESTABLISHED = 2,
            CLOSING = 3,
        };



          struct alignas(16) TcpKey {
            uint32_t src_ip{0};
            uint32_t dst_ip{0};
            uint16_t src_port{0};
            uint16_t dst_port{0};
            uint32_t _pad{0}; 
            AETHON_ALWAYS_INLINE bool operator==(const TcpKey &o) const noexcept {
                return src_ip == o.src_ip &&
                       dst_ip == o.dst_ip &&
                       src_port == o.src_port &&
                       dst_port == o.dst_port;
            }
            AETHON_ALWAYS_INLINE bool operator!=(const TcpKey &o) const noexcept {
                return !(*this == o);
            }
        };


        struct TcpKeyHasher {
            AETHON_ALWAYS_INLINE size_t operator()(const TcpKey &k) const noexcept {
                uint64_t h1 = (static_cast<uint64_t>(k.src_ip) << 32) | k.dst_ip;
                uint64_t h2 = (static_cast<uint64_t>(k.src_port) << 16) | k.dst_port;
                
                h1 ^= h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
                h1 ^= h1 >> 30;
                h1 *= 0xbf58476d1ce4e5b9ULL;
                h1 ^= h1 >> 27;
                h1 *= 0x94d049bb133111ebULL;
                h1 ^= h1 >> 31;
                return static_cast<size_t>(h1);
            }
        };


        static constexpr TcpKey KemptyTcpKey {0,0,0,0,0};
        struct TcpSeq{
             AETHON_ALWAYS_INLINE static bool lt(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) < 0;
            }
            AETHON_ALWAYS_INLINE static bool lte(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) <= 0;
            }
            AETHON_ALWAYS_INLINE static bool gt(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) > 0;
            }
            AETHON_ALWAYS_INLINE static bool gte(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) >= 0;
            }
            AETHON_ALWAYS_INLINE static uint32_t diff(uint32_t a, uint32_t b) noexcept {
                return a - b;
            }
        };


        struct TcpNegotiatedParams{
            uint16_t mss{1460}; // mtu
            uint8_t  client_wscale{0}; 
            uint8_t  server_wscale{0};
            bool     wscale_enabled{false}; 
            bool sack_permitted{false};
        };

        AETHON_ALWAYS_INLINE static void parse_tcp_syn_option(const struct tcphdr * __restrict__ tcph,TcpNegotiatedParams &out_params) noexcept{
            
            // tcp header length
            const size_t tcp_hdr_len = tcph->doff * 4;

            if(AETHON_UNLIKELY(tcp_hdr_len <= sizeof(struct tcphdr))){
                return ;
            }
            
            const uint8_t *__restrict__ opt = reinterpret_cast<const uint8_t *>(tcph) + sizeof(struct tcphdr);
            const uint8_t *__restrict__ end = reinterpret_cast<const uint8_t *>(tcph) + tcp_hdr_len;

            while (opt < end) {
                const uint8_t kind = *opt;
                if(kind == TCPOPT_EOL){
                    break; // end of list
                }
                if(kind == TCPOPT_NOP){
                    ++opt;
                    continue;
                }

                // kind 1 byte length 1 byte value 2 byte

                if(AETHON_UNLIKELY(opt + 1 >= end)){
                    break;
                }

                const uint8_t len = *(opt + 1);
                if(AETHON_UNLIKELY(len <2 || opt + len > end)) break;

                switch (kind) {
                    case TCPOPT_MAXSEG: // kind 2 : mSS (length 4)
                        if(AETHON_LIKELY(len == TCPOLEN_MAXSEG)){
                            out_params.mss =  ntohs(*reinterpret_cast<const uint16_t *>(opt + 2));
                        }
                        break;
                        
                    case TCPOPT_WINDOW: // kind 3 window scale (length = 3)
                        if(AETHON_LIKELY(len == TCPOLEN_WINDOW)){
                            out_params.wscale_enabled = true;
                            // RFC 7323 Section 2.3: Shift counts > 14 are invalid; clamp to 14
                            out_params.client_wscale =  std::min<uint8_t>(*(opt + 2), 14);
                            out_params.server_wscale = 7;
                        }
                        break;
                    
                    case TCPOPT_SACK_PERMITTED:
                        if(AETHON_LIKELY(len == TCPOLEN_SACK_PERMITTED)){
                            out_params.sack_permitted = true;
                        }
                        break;
                    default:
                        break;
                }

                opt+=len;
            }



        }

        static constexpr size_t AETHON_MAX_ACTIVE_TCP_SESSION = config::tcp::MAX_ACTIVE_TCP_SESSION;
        static constexpr size_t AETHON_TCP_WINDOW_SIZE = config::tcp::TCP_WINDOW_SIZE;
        static constexpr size_t AETHON_TCP_BITMAP_WORDS        = config::tcp::TCP_BITMAP_WORDS; 
        static constexpr uint64_t AETHON_TCP_SYN_TIMEOUT_NS    = config::tcp::SYN_TIMEOUT_NS;
        // Longer than common backend keep-alive timeouts (nginx: 65 s), so idle keep-alive
        // connections are closed cleanly by the backend (FIN) before Aethon forgets them.
        static constexpr uint64_t AETHON_TCP_ESTAB_TIMEOUT_NS  = config::tcp::ESTAB_TIMEOUT_NS;
        static constexpr uint64_t AETHON_TCP_TIMEWAIT_TIMEOUT_NS = config::tcp::TIMEWAIT_TIMEOUT_NS;  // half-closed / FIN'd
        // Above this many sessions per worker, new SYNs are answered with SYN cookies
        // (no state until the client completes the handshake).
        static constexpr size_t AETHON_SYNCOOKIE_THRESHOLD = config::tcp::SYNCOOKIE_THRESHOLD;


        struct TcpStreamSession;
        struct TcpAssemblyResult{
             bool is_ready{false};
            bool is_syn{false};
            bool is_closed{false};
            bool is_fin{false};
            bool need_ack{false};
            uint16_t src_port{0};
            uint16_t dst_port{0};
            const uint8_t *payload{nullptr};
            size_t payload_len{0};
            TcpStreamSession *session{nullptr};
            hs_stream_t *hs_stream{nullptr};
            hs_stream_t *custom_hs_stream{nullptr};
            uint64_t custom_hs_gen{0};
            bool fast_retransmit{false};
            bool syn_cookie{false};          // answer this SYN statelessly with ISN = syn_cookie_isn
            uint32_t syn_cookie_isn{0};
            bool from_cookie{false};         // session was just created from a valid SYN cookie
            bool overlap_violation{false};   // session killed: retransmission contradicts buffered data
        };

        /**
         * @brief Zero-overhead O(1) TCP Outbound Send Buffer
         * 
         * Eliminates O(n^2) std::vector::erase(begin()) front-shifting memmove on every ACK.
         * Uses an O(1) head offset and compacts only amortized when the head passes half
         * the buffer and >= 128 KB, maintaining wire-rate memory efficiency without cache thrashing.
         */
        class alignas(16) TcpSendBuffer {
        private:
            std::vector<uint8_t> buf_;
            size_t head_{0};

        public:
            TcpSendBuffer() noexcept = default;

            AETHON_ALWAYS_INLINE size_t size() const noexcept {
                return (buf_.size() > head_) ? (buf_.size() - head_) : 0;
            }

            AETHON_ALWAYS_INLINE bool empty() const noexcept {
                return size() == 0;
            }

            AETHON_ALWAYS_INLINE const uint8_t* data() const noexcept {
                return buf_.data() + head_;
            }

            AETHON_ALWAYS_INLINE uint8_t* data() noexcept {
                return buf_.data() + head_;
            }

            AETHON_ALWAYS_INLINE void append(const uint8_t* data, size_t len) {
                if (!data || len == 0) return;
                // If head has advanced significantly, compact to recycle capacity
                if (head_ > 0 && (head_ >= 131072 || head_ >= buf_.size() / 2)) {
                    compact();
                }
                buf_.insert(buf_.end(), data, data + len);
            }

            AETHON_ALWAYS_INLINE void consume(size_t bytes) noexcept {
                head_ += bytes;
                if (head_ >= buf_.size()) {
                    clear();
                } else if (head_ >= 131072 && head_ >= buf_.size() / 2) {
                    compact();
                }
            }

            AETHON_ALWAYS_INLINE void clear() noexcept {
                buf_.clear();
                head_ = 0;
            }

            AETHON_ALWAYS_INLINE void compact() noexcept {
                if (head_ == 0) return;
                size_t remaining = buf_.size() - head_;
                if (remaining > 0) {
                    std::memmove(buf_.data(), buf_.data() + head_, remaining);
                    buf_.resize(remaining);
                } else {
                    buf_.clear();
                }
                head_ = 0;
            }

            AETHON_ALWAYS_INLINE size_t capacity_bytes() const noexcept {
                return buf_.capacity();
            }
        };

        struct alignas(implementation::hardware_destructive_interference_size)
        TcpStreamSession{
            TcpKey key{KemptyTcpKey};
            TcpState state{TcpState::CLOSED};
            uint8_t _pad0{0};
            uint16_t _pad1{0};
            uint32_t ooo_bytes{0};          // exact number of bytes buffered in the ring ahead of rcv_nxt
            uint32_t isn{0};
            uint32_t server_isn{0};         // RFC 6528: Server Initial Sequence Number (randomized)
            uint32_t rcv_nxt{0};
            uint64_t last_seen_ns{0};
            TcpNegotiatedParams params{};

            ReassemblyBufferPool *pool_{nullptr};
            ReassemblyBuffer *reassembly_buf{nullptr};
            uint64_t *bitmap{nullptr};
            uint8_t  *ring_buf{nullptr};

            tls::TlsConnection tls_conn;

            int backend_fd {-1};
            uint16_t backend_port {0};
            bool is_http{false};
            static constexpr size_t MAX_BACKEND_BUF = config::tcp::MAX_BACKEND_BUF;
            std::vector<uint8_t> backend_tx_buf;
            bool epollout_armed{false};
            bool backend_epollin_disabled{false};

            /*
                send_una                                       send_nxt
            [Already Acked]| In flight in snd_buf(3KB)   |    (Not sent yet)    ]     

            */

            // Outbound TCP Reliability State
            uint32_t snd_una{0};                       // Oldest unacknowledged sequence number
            uint32_t snd_wnd{65535};                   // Client's advertised receive window (starts at 64 KB)
            static constexpr size_t MAX_SND_BUF = config::tcp::MAX_SND_BUF;
            TcpSendBuffer snd_buf;                     // O(1) Data in-flight or waiting to be sent
            uint64_t last_tx_time_ns{0};               // Timestamp of last transmission
            uint32_t rto_ms{config::tcp::INITIAL_RTO_MS}; // RTO in milliseconds (RFC 6298: 1s initial)
            uint8_t retransmit_count{0};               // Number of retransmissions

            // RFC 6298: Dynamic RTT and RTO estimation (Jacobson's Algorithm)
            uint32_t srtt_ms{0};                       // Smoothed round-trip time
            uint32_t rttvar_ms{0};                     // Round-trip time variation
            uint64_t synack_tx_time_ns{0};             // Timestamp of SYN-ACK transmission for handshake RTT
            uint32_t rtt_seq{0};                       // TCP seq number tracked for RTT sample
            uint64_t rtt_time_ns{0};                   // Timestamp when rtt_seq was transmitted

            AETHON_ALWAYS_INLINE void update_rtt(uint32_t sample_ms) noexcept {
                if (sample_ms == 0) sample_ms = 1;
                if (AETHON_UNLIKELY(srtt_ms == 0)) {
                    // RFC 6298 Section 2.2: First RTT measurement
                    // SRTT <- R, RTTVAR <- R/2
                    srtt_ms = sample_ms;
                    rttvar_ms = sample_ms >> 1;
                } else {
                    // RFC 6298 Section 2.3: Subsequent RTT measurements
                    // alpha = 1/8 (0.125), beta = 1/4 (0.25)
                    // RTTVAR <- (3/4) * RTTVAR + (1/4) * |SRTT - sample|
                    // SRTT   <- (7/8) * SRTT + (1/8) * sample
                    int32_t delta = static_cast<int32_t>(srtt_ms) - static_cast<int32_t>(sample_ms);
                    if (delta < 0) delta = -delta;
                    rttvar_ms = (3 * rttvar_ms + static_cast<uint32_t>(delta)) >> 2;
                    srtt_ms = (7 * srtt_ms + sample_ms) >> 3;
                }
                // RFC 6298 Section 2.4: RTO = SRTT + 4 * RTTVAR, clamped to [200 ms, 60000 ms]
                rto_ms = std::min(std::max(srtt_ms + (rttvar_ms << 2), 200u), 60000u);
            }

            uint8_t dup_ack_count{0};                      // Number of duplicate ACKs received
            tcp::TcpRenoCongestionControl cc;              // Congestion Control (cwnd, ssthresh)
            // Compute dynamic receive window based on remaining buffer capacity

            bool fin_pending{false};          // backend reached EOF ; defer FIN until send_buf drains
            bool fin_sent{false};             // our FIN has been sent; waiting for client ACK
            bool client_fin_received{false};  // client sent FIN (half-closed request)


            AETHON_ALWAYS_INLINE uint16_t recv_window() const noexcept {
                // Undecrypted TLS bytes are already ACKed but not yet in backend_tx_buf; count them,
                // otherwise a burst of completed records can overflow MAX_BACKEND_BUF (-> RST)

                if(AETHON_UNLIKELY(budget && budget->is_over_budget())){
                    return 0;
                }

                size_t used = backend_tx_buf.size() + tls_conn.pending_input();
                if (used >= MAX_BACKEND_BUF) return 0;
                size_t remaining = MAX_BACKEND_BUF - used;
                if (params.wscale_enabled && params.server_wscale > 0) {
                    remaining >>= params.server_wscale;
                }
                return static_cast<uint16_t>(std::min<size_t>(65535, remaining));
            }

            hs_stream_t *hs_stream{nullptr};
            hs_stream_t *custom_hs_stream{nullptr};
            uint64_t custom_hs_gen{0};

            uint8_t client_mac[6]{0};
            uint8_t server_mac[6]{0};
            uint32_t send_nxt{0};


            WorkerMemoryBudget *budget{nullptr};

            struct SackBlock{
                uint32_t left_edge{0};
                uint32_t right_edge{0};
            };

            static constexpr size_t MAX_SACK_BLOCKS = config::tcp::MAX_SACK_BLOCKS;
            std::array<SackBlock, MAX_SACK_BLOCKS> client_sack_blocks{};
            uint8_t num_sack_blocks{0};

            // check if a sequence number was already received by the client
            AETHON_ALWAYS_INLINE bool is_sacked(uint32_t seq) const noexcept {
                for (uint8_t i = 0; i < num_sack_blocks; ++i) {
                    if (TcpSeq::gte(seq, client_sack_blocks[i].left_edge) &&
                        TcpSeq::lt(seq, client_sack_blocks[i].right_edge)) {
                        return true;
                    }
                }
                return false;
            }

            std::vector<uint8_t> client_hello_buf;
            bool app_data_seen{false};      // first in-order payload byte already processed

            TcpStreamSession() = default;

            ~TcpStreamSession() {
                if(backend_fd >=0){
                    ::close(backend_fd);
                    backend_fd = -1;
                }

                release_buffers();

                if(hs_stream){
                    hs_close_stream(hs_stream, nullptr, nullptr, nullptr);
                    hs_stream = nullptr;
                }
                if(custom_hs_stream){
                    hs_close_stream(custom_hs_stream, nullptr, nullptr, nullptr);
                    custom_hs_stream = nullptr;
                }

                 if (budget) {
                        budget->deallocate(snd_buf.size() + backend_tx_buf.size() + client_hello_buf.size());
                    }
            }
            TcpStreamSession(const TcpStreamSession &) = delete;
            TcpStreamSession &operator=(const TcpStreamSession &) = delete;


            AETHON_ALWAYS_INLINE bool flush_backend_tx() noexcept {
                if(backend_fd < 0 || backend_tx_buf.empty()) return true;
                ssize_t sent = ::send(backend_fd, backend_tx_buf.data(), backend_tx_buf.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent > 0) {
                    backend_tx_buf.erase(backend_tx_buf.begin(), backend_tx_buf.begin() + sent);
                }
                return backend_tx_buf.empty();
            }

            AETHON_ALWAYS_INLINE bool init_buffers(ReassemblyBufferPool &pool) noexcept {
                if (AETHON_LIKELY(reassembly_buf != nullptr)) {
                    return true;
                }

                reassembly_buf = pool.acquire();
                if (AETHON_UNLIKELY(!reassembly_buf)) {
                    return false;
                }
                pool_ = &pool;
                ring_buf = reassembly_buf->data;
                bitmap = reassembly_buf->bitmap;
                return true;
            }

            AETHON_ALWAYS_INLINE void release_buffers() noexcept {
                if (reassembly_buf) {
                    if (pool_) {
                        pool_->release(reassembly_buf);
                        pool_ = nullptr;
                    }
                    reassembly_buf = nullptr;
                    ring_buf = nullptr;
                    bitmap = nullptr;
                }
            }

            AETHON_ALWAYS_INLINE bool forward_to_backend(const uint8_t *data, size_t len, uint16_t target_port) noexcept {
                if(AETHON_UNLIKELY(!data || len == 0 || target_port ==0)){
                    return false;
                }

                if(AETHON_UNLIKELY(backend_fd < 0 || backend_port != target_port)){
                    if(backend_fd >=0){
                        ::close(backend_fd);
                        backend_fd = -1;
                    }

                    backend_tx_buf.clear();

                    // sock stream tcp connection SOCK_NONBLOCK --> any operation on this sockets returns immediately
                    backend_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                    if(backend_fd < 0){
                        return false;
                    }

                    int one = 1;
                    //  TCP_NODELAY send packets immediately as soon as we write to the socket
                    setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    struct linger sl = {1, 0};
                    setsockopt(backend_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
                    struct sockaddr_in sin {};
                    sin.sin_family  = AF_INET;
                    sin.sin_port = htons(target_port);
                    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                    connect(backend_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin));
                    backend_port = target_port;
                    // Bound the pending write buffer to protect against OOM
                    if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                    return true;
                }

                if(!backend_tx_buf.empty()){
                    // Check capacity before buffering in case backend is slow
                    if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                    flush_backend_tx();
                    return true;
                }

                // MSG_DONTWAIT : Guarantees non-blocking 
                // MSG_NOSIGNAL : if the backend server crashed prevenr linux from raising a SIGPIPE signal which would kill our entire process
                ssize_t sent = ::send(backend_fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
                if(sent < 0){
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                            return false;
                        }
                        backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                        return true;
                    }
                    return false;
                }

                if(static_cast<size_t>(sent) < len){
                    size_t unsent = len - sent;
                    if (backend_tx_buf.size() + unsent > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data + sent, data + len);
                }
                return true;
            }


            AETHON_ALWAYS_INLINE ssize_t read_from_backend(uint8_t * buf, size_t max_len, int timeout_ms = 50) noexcept {
                 if(AETHON_UNLIKELY(backend_fd < 0 || !buf || max_len == 0)){
                    return -1;
                }
                return  ::recv(backend_fd, buf, max_len, MSG_DONTWAIT);
                
            }

            
            AETHON_ALWAYS_INLINE void write_ring_buffer(size_t start, const uint8_t * __restrict__ data,size_t len) noexcept{
                start&=0xFFFF;

                AETHON_BUILTIN_PREFETCH(&ring_buf[start], 1, 3);
                if(AETHON_UNLIKELY(start + len  > AETHON_TCP_WINDOW_SIZE)){
                    size_t first = AETHON_TCP_WINDOW_SIZE - start;
                    std::memcpy(&ring_buf[start],data,first);
                    std::memcpy(&ring_buf[0], data + first, len-first);
                }else{
                     std::memcpy(&ring_buf[start], data, len);
                }

            }


            AETHON_ALWAYS_INLINE void read_ring_buffer(size_t start, uint8_t * __restrict__ out, size_t len) const noexcept {
                start &= 0xFFFF;
                AETHON_BUILTIN_PREFETCH(&ring_buf[start], 0, 3);
                if (AETHON_UNLIKELY(start + len > AETHON_TCP_WINDOW_SIZE)) {
                    size_t first = AETHON_TCP_WINDOW_SIZE - start;
                    std::memcpy(out, &ring_buf[start], first);
                    std::memcpy(out + first, &ring_buf[0], len - first);
                } else {
                    std::memcpy(out, &ring_buf[start], len);
                }
            }

            
            // Returns how many bits were newly set (bytes not buffered before)
            AETHON_ALWAYS_INLINE size_t set_bitmap_range(size_t start, size_t count) noexcept{
                start&=0xFFFF;
                size_t newly_set = 0;
                while (count>0) {
                    size_t word_idx = start >> 6; // divide by 64
                    size_t bit_offset = start & 63; // % 64

                    size_t bits_in_word =64 - bit_offset;

                    size_t n = (count < bits_in_word) ? count : bits_in_word;

                    uint64_t mask = ((n == 64) ? ~0ULL : ((1ULL << n) - 1ULL)) << bit_offset;
                    newly_set += static_cast<size_t>(__builtin_popcountll(mask & ~bitmap[word_idx]));
                    bitmap[word_idx]|= mask;
                    start = (start + n) & 0xFFFF;
                    count-=n;
                }
                return newly_set;
            }

              // Returns how many bits were actually cleared (bytes that were buffered)
              AETHON_ALWAYS_INLINE size_t clear_bitmap_range(size_t start, size_t count) noexcept {
                start &= 0xFFFF;
                size_t cleared = 0;
                while (count > 0) {
                    size_t word_idx = start >> 6;
                    size_t bit_offset = start & 63;
                    size_t bits_in_word = 64 - bit_offset;
                    size_t n = (count < bits_in_word) ? count : bits_in_word;
                    uint64_t mask = ((n == 64) ? ~0ULL : ((1ULL << n) - 1ULL)) << bit_offset;
                    cleared += static_cast<size_t>(__builtin_popcountll(mask & bitmap[word_idx]));
                    bitmap[word_idx] &= ~mask;
                    start = (start + n) & 0xFFFF;
                    count -= n;
                }
                return cleared;
            }

            // Overlap evasion check: true if any byte that is ALREADY buffered (bitmap bit set)
            // differs from the new data. Unbuffered positions hold stale ring data and are skipped,
            // so a retransmission with different segment boundaries is not mistaken for an attack.
            AETHON_ALWAYS_INLINE bool conflicts_with_buffered(uint32_t seq, const uint8_t *data, size_t len) const noexcept {
                if (!bitmap || !ring_buf) return false;
                for (size_t i = 0; i < len; ++i) {
                    size_t pos = (seq + i) & 0xFFFF;
                    if (((bitmap[pos >> 6] >> (pos & 63)) & 1ULL) && ring_buf[pos] != data[i]) {
                        return true;
                    }
                }
                return false;
            }

            AETHON_ALWAYS_INLINE bool is_range_set(size_t start, size_t count) const noexcept {
                if (!bitmap || count == 0) return false;
                start &= 0xFFFF;
                while (count > 0) {
                    size_t word_idx = start >> 6;
                    size_t bit_offset = start & 63;
                    size_t bits_in_word = 64 - bit_offset;
                    size_t n = (count < bits_in_word) ? count : bits_in_word;
                    uint64_t mask = (n == 64) ? ~0ULL : ((1ULL << n) - 1ULL);
                    if ((bitmap[word_idx] & (mask << bit_offset)) != 0) {
                        return true;
                    }
                    start = (start + n) & 0xFFFF;
                    count -= n;
                }
                return false;
            }


            AETHON_ALWAYS_INLINE size_t count_continuous_bytes(uint32_t start_seq, size_t max_bytes) const noexcept{
                size_t assembled = 0;
                while (assembled < max_bytes) {
                    size_t idx = (start_seq + assembled) & 0xFFFF;
                    size_t word_idx = idx>>6;
                    size_t bit_offset = idx & 63;

                    uint64_t word  = bitmap[word_idx]  >> bit_offset;
                    
                    // hole
                    if((word & 1ULL) ==0){
                        break; 
                    }

                    uint64_t inverted = ~word;

                    size_t contiguous = (inverted == 0 ) ? (64 - bit_offset) : static_cast<size_t>(__builtin_ctzll(inverted));
                    size_t available_in_word = 64 - bit_offset;

                    if(contiguous > available_in_word){
                        contiguous = available_in_word;
                    }

                    if(assembled + contiguous > max_bytes){
                        contiguous = max_bytes - assembled;
                    }

                    assembled+=contiguous;

                    if(contiguous < available_in_word){
                        break;
                    }
                }

                return assembled;
            }


        };

        AETHON_ALWAYS_INLINE static void parse_tcp_ack_options(
            const struct tcphdr * __restrict__ tcph,
            TcpStreamSession * __restrict__ session
        ) noexcept {
            const size_t tcp_hdr_len = tcph->doff * 4;
            if (AETHON_LIKELY(tcp_hdr_len <= sizeof(struct tcphdr) || !session->params.sack_permitted)) {
                return;
            }

            const uint8_t *opt = reinterpret_cast<const uint8_t *>(tcph) + sizeof(struct tcphdr);
            const uint8_t *end = reinterpret_cast<const uint8_t *>(tcph) + tcp_hdr_len;

            while (opt < end) {
                const uint8_t kind = *opt;
                if (kind == TCPOPT_EOL) break;
                if (kind == TCPOPT_NOP) {
                    ++opt;
                    continue;
                }

                if (AETHON_UNLIKELY(opt + 1 >= end)) break;
                const uint8_t len = *(opt + 1);
                if (AETHON_UNLIKELY(len < 2 || opt + len > end)) break;

                // Kind 5: SACK option (RFC 2018)
                if (kind == 5 && (len - 2) % 8 == 0) {
                    uint8_t num_blocks = static_cast<uint8_t>((len - 2) / 8);
                    session->num_sack_blocks = std::min<uint8_t>(num_blocks, TcpStreamSession::MAX_SACK_BLOCKS);
                    const uint8_t *block_ptr = opt + 2;
                    for (uint8_t i = 0; i < session->num_sack_blocks; ++i) {
                        session->client_sack_blocks[i].left_edge = ntohl(*reinterpret_cast<const uint32_t *>(block_ptr));
                        session->client_sack_blocks[i].right_edge = ntohl(*reinterpret_cast<const uint32_t *>(block_ptr + 4));
                        block_ptr += 8;
                    }
                }

                opt += len;
            }
        }

        class alignas(implementation::hardware_destructive_interference_size)
        TcpAssemblerEngine{
            private:
                 using SessionMap = aethon::SingleThreadHashMap<TcpKey, TcpStreamSession*, KemptyTcpKey, TcpKeyHasher>;

                 SessionMap sessions_{AETHON_MAX_ACTIVE_TCP_SESSION * 2};
                 // we copy and fallten that assembled data out of the ring buffer
                 alignas(implementation::hardware_destructive_interference_size) std::array<uint8_t, AETHON_TCP_WINDOW_SIZE> drain_buf_{};

                 uint64_t last_cleanup_ns_{0};
                 ReassemblyBufferPool reassembly_pool_;
                 WorkerMemoryBudget budget_;
                 // SYN cookie secret (per worker; a flow always returns to the same worker)
                 uint64_t cookie_k0_{0};
                 uint64_t cookie_k1_{0};
                 static constexpr uint64_t kCookieSlotNs = config::tcp::COOKIE_SLOT_NS;   // 64 s time slots

                 static AETHON_ALWAYS_INLINE uint64_t rotl(uint64_t x, int b) noexcept {
                     return (x << b) | (x >> (64 - b));
                 }

                 // SipHash-2-4 of three 64-bit words (24 bytes)
                 AETHON_ALWAYS_INLINE uint64_t siphash3(uint64_t m0, uint64_t m1, uint64_t m2) const noexcept {
                     uint64_t v0 = 0x736f6d6570736575ULL ^ cookie_k0_;
                     uint64_t v1 = 0x646f72616e646f6dULL ^ cookie_k1_;
                     uint64_t v2 = 0x6c7967656e657261ULL ^ cookie_k0_;
                     uint64_t v3 = 0x7465646279746573ULL ^ cookie_k1_;
                     auto round = [&]() noexcept {
                         v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
                         v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
                         v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
                         v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
                     };
                     for (uint64_t m : {m0, m1, m2}) {
                         v3 ^= m; round(); round(); v0 ^= m;
                     }
                     const uint64_t last = 24ULL << 56;          // message length in the final block
                     v3 ^= last; round(); round(); v0 ^= last;
                     v2 ^= 0xff;
                     round(); round(); round(); round();
                     return v0 ^ v1 ^ v2 ^ v3;
                 }

                 AETHON_ALWAYS_INLINE uint32_t cookie_mac(const TcpKey &k, uint32_t client_isn, uint32_t slot) const noexcept {
                     const uint64_t m0 = static_cast<uint64_t>(k.src_ip) | (static_cast<uint64_t>(k.dst_ip) << 32);
                     const uint64_t m1 = static_cast<uint64_t>(k.src_port) | (static_cast<uint64_t>(k.dst_port) << 16) |
                                         (static_cast<uint64_t>(client_isn) << 32);
                     return static_cast<uint32_t>(siphash3(m0, m1, slot)) & 0x07FFFFFFu;
                 }

            public:
                TcpAssemblerEngine() {
                    std::random_device rd;
                    cookie_k0_ = (static_cast<uint64_t>(rd()) << 32) | rd();
                    cookie_k1_ = (static_cast<uint64_t>(rd()) << 32) | rd();
                }

                // Cookie layout: [5 bits time slot][27 bits SipHash MAC of 4-tuple + client ISN + slot]
                AETHON_ALWAYS_INLINE uint32_t make_syn_cookie(const TcpKey &k, uint32_t client_isn, uint64_t now_ns) const noexcept {

                    // 5 bits range from 0 to 31 so every 64 seconds this numbers increades by 1 first 64 seconds 0, next 64 seconds 1, next 64 second 2 , like that 
                    // SO TOTAL 32 * 64 = 34 MINUTES 
                    const uint32_t slot = static_cast<uint32_t>(now_ns / kCookieSlotNs) & 0x1F;
                    return (slot << 27) | cookie_mac(k, client_isn, slot);
                }

                // Valid for the current and the previous slot (64-128 s)
                AETHON_ALWAYS_INLINE bool check_syn_cookie(const TcpKey &k, uint32_t client_isn, uint32_t cookie, uint64_t now_ns) const noexcept {
                    const uint32_t slot = cookie >> 27;
                    const uint32_t now_slot = static_cast<uint32_t>(now_ns / kCookieSlotNs) & 0x1F;
                    if (((now_slot - slot) & 0x1F) > 1) return false;
                    return (cookie & 0x07FFFFFFu) == cookie_mac(k, client_isn, slot);
                }

                size_t session_count() const noexcept { return sessions_.size(); }
                WorkerMemoryBudget &memory_budget() noexcept { return budget_; }
                const WorkerMemoryBudget &memory_budget() const noexcept { return budget_; }

                ~TcpAssemblerEngine(){

                }

                TcpAssemblerEngine (const TcpAssemblerEngine&) = delete;
                TcpAssemblerEngine &operator=(const TcpAssemblerEngine &) = delete;

                template <typename Fn>
                void for_each_session(Fn &&fn) noexcept {
                    for (size_t i = 0; i < sessions_.capacity(); ++i) {
                        auto *cell = &sessions_.cells()[i];
                        if (cell->key != KemptyTcpKey && cell->val) {
                            fn(cell->val);
                        }
                    }
                }

                void clear() noexcept{
                    for(size_t i = 0; i< sessions_.capacity(); i++){
                        auto *cell = &sessions_.cells()[i];
                        if(cell->key != KemptyTcpKey){
                            delete cell->val;
                            cell->val = nullptr;
                            cell->key = KemptyTcpKey;
                        }
                    }
                }

            void purged_expired(uint64_t now_ns) noexcept {
                const bool critical_memory = budget_.is_critical();

                for (size_t i = 0; i < sessions_.capacity(); ++i) {
                    AETHON_BUILTIN_PREFETCH(&sessions_.cells()[i], 0, 1);
                    auto *cell = &sessions_.cells()[i];
                    if (cell->key != KemptyTcpKey) {
                        TcpStreamSession *session = cell->val;
                        if (session) {
                            uint64_t age = now_ns - session->last_seen_ns;
                            // A session with unacknowledged or queued outbound data is still
                            // actively delivering (e.g. the response + our FIN, retransmitting under
                            // loss) and must NOT be reaped early, whatever its state.
                            const bool has_outbound = (session->snd_una != session->send_nxt) ||
                                                      !session->snd_buf.empty();
                            // SYN_SENT: 3 s. Quiescent half-closed / FIN'd (TIME_WAIT-like): 10 s, so
                            // abandoned connections are reclaimed quickly instead of holding memory
                            // for the full established idle timeout. Everything else: 120 s (longer
                            // than typical backend keep-alive).



                            // under critical memory pressure aggresively evict idle connections(5s threashold)
                            uint64_t limit;
                            if (session->state == TcpState::SYN_SENT) {
                                limit = AETHON_TCP_SYN_TIMEOUT_NS;
                            } else if (AETHON_UNLIKELY(critical_memory)) {
                                limit = config::memory::CRITICAL_EVICTION_AGE_NS;
                            } 
                            else if (!has_outbound && (session->state == TcpState::CLOSING || session->fin_sent)) {
                                limit = AETHON_TCP_TIMEWAIT_TIMEOUT_NS;
                            } else {
                                limit = AETHON_TCP_ESTAB_TIMEOUT_NS;
                            }
                            bool is_expired = age > limit;
                            if (AETHON_UNLIKELY(is_expired)) {
                                if (critical_memory && age > config::memory::CRITICAL_EVICTION_AGE_NS && session->state == TcpState::ESTABLISHED) {
                                    stats::count(stats::Event::SessionEvictedMemoryPressure);
                                } else if (session->state != TcpState::SYN_SENT) {
                                    stats::count(stats::Event::SessionExpiredIdle);
                                }
                                TcpKey stale_key = cell->key;
                                delete session;
                                sessions_.erase(stale_key);
                            }
                        }
                    }
                }
            }

            // Run the idle-session reaper at most once per second. The per-packet path already
            // does this, but when traffic stops no packets arrive, so stale TIME_WAIT / idle
            // sessions would never be reaped and the worker would busy-poll forever. The worker
            // calls this from its idle loop so sessions still drain with no traffic.
            AETHON_ALWAYS_INLINE void reap_if_due(uint64_t now_ns) noexcept {
                if (now_ns - last_cleanup_ns_ > 1000000000ULL) {
                    purged_expired(now_ns);
                    last_cleanup_ns_ = now_ns;
                }
            }

            void close_session(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) noexcept {
                TcpKey key;
                key.src_ip = src_ip;
                key.dst_ip = dst_ip;
                key.src_port = src_port;
                key.dst_port = dst_port;
                TcpStreamSession **slot = sessions_.find(key);
                if (slot && *slot) {
                    delete *slot;
                    sessions_.erase(key);
                }
            }

            bool handle_icmp_pmtu(uint32_t client_ip, uint16_t client_port,
                                  uint32_t server_ip, uint16_t server_port,
                                  uint16_t next_hop_mtu) noexcept {
                TcpKey key;
                key.src_ip   = client_ip;
                key.dst_ip   = server_ip;
                key.src_port = client_port;
                key.dst_port = server_port;

                TcpStreamSession **slot = sessions_.find(key);
                if (AETHON_UNLIKELY(slot == nullptr || *slot == nullptr)) {
                    return false;
                }

                TcpStreamSession *session = *slot;

                // RFC 1191 Path MTU Discovery:
                // Next-Hop MTU is provided in the ICMP header. Standard IPv4 header (20B)
                // + TCP header (20B) gives 40 bytes minimum L3/L4 overhead.
                uint16_t new_mss = config::tcp::MIN_IPV4_MSS;
                if (next_hop_mtu > 40) {
                    new_mss = next_hop_mtu - 40;
                } else if (session->params.mss > config::tcp::MIN_IPV4_MSS) {
                    // Plateau descent (RFC 1191 Table 7-1)
                    if (session->params.mss > 1420) new_mss = 1420;
                    else if (session->params.mss > 1240) new_mss = 1240;
                    else new_mss = config::tcp::MIN_IPV4_MSS;
                }

                // Minimum IPv4 MSS guaranteed by RFC 791 / RFC 879 is 536 bytes
                new_mss = std::clamp(new_mss, static_cast<uint16_t>(config::tcp::MIN_IPV4_MSS), session->params.mss);

                if (new_mss < session->params.mss) {
                    session->params.mss = new_mss;
                    session->cc.mss = new_mss;
                    // Reset congestion window to force fast adaptation and avoid oversized frames
                    session->cc.ssthresh = std::max<uint32_t>(2 * new_mss, session->cc.cwnd / 2);
                    session->cc.cwnd = 1 * new_mss;
                    stats::count(stats::Event::IcmpPmtuUpdate);
                    return true;
                }
                return false;
            }

            // process packet

            AETHON_ALWAYS_INLINE TcpAssemblyResult process_packet(
                const struct iphdr * __restrict__ iph,
                const struct tcphdr * __restrict__ tcph,
                const uint8_t * __restrict__ payload,
                uint16_t payload_len,
                uint64_t now_ns
            ) noexcept{
                TcpAssemblyResult result;
                AETHON_BUILTIN_PREFETCH(iph, 0, 3);
                AETHON_BUILTIN_PREFETCH(tcph, 0, 3);
                if (payload_len > 0) {
                    AETHON_BUILTIN_PREFETCH(payload, 0, 3);
                }



                bool do_cleanup = (now_ns - last_cleanup_ns_ > 1000000000ULL);
                if(AETHON_UNLIKELY(!do_cleanup && budget_.is_critical() && last_cleanup_ns_ > 50000000ULL)){
                    do_cleanup = true; //  // Trigger every 50ms instead of 1000ms!
                }


                /*
                    Out of those 2,000,000 packets in 1 second 
                    Exactly 1 single packet will trigger the 1-second cleanup.
                */
                if(AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(now_ns - last_cleanup_ns_ > 1000000000ULL, 0, 0.999999)){
                    purged_expired(now_ns);
                    last_cleanup_ns_ =now_ns;
                }


                TcpKey key;
                
                key.src_ip   = iph->saddr;
                key.dst_ip   = iph->daddr;
                key.src_port = tcph->source;
                key.dst_port = tcph->dest;
                result.src_port = ntohs(tcph->source);
                result.dst_port = ntohs(tcph->dest);

                const uint8_t flags = reinterpret_cast<const uint8_t *>(tcph)[13];
                const uint32_t seq   = ntohl(tcph->seq);

                TcpStreamSession **slot = sessions_.find(key);
                TcpStreamSession *session = nullptr;

                if(AETHON_LIKELY(slot != nullptr)){
                    session = *slot;
                    AETHON_BUILTIN_PREFETCH(session, 1, 3);
                    result.session = session;

                    // If a brand-new SYN arrives for a session that is closing, half-closed, or whose backend is gone:
                    // Client is reincarnating the socket / port reuse (RFC 1122 Section 4.2.2.13).
                    if (AETHON_UNLIKELY((flags & TH_SYN) && session->state != TcpState::SYN_SENT)) {
                        if (session->state == TcpState::CLOSING || session->fin_sent || session->client_fin_received || session->backend_fd < 0) {
                            delete session;
                            sessions_.erase(key);
                            session = nullptr;
                            result.session = nullptr;
                        }
                    }
                }
                
                if (session == nullptr) {
                    if (AETHON_UNLIKELY(!(flags & TH_SYN))) {
                        // No session: only a handshake ACK (or first data) carrying a valid SYN cookie may create one
                        if ((flags & TH_ACK) && !(flags & (TH_RST | TH_FIN)) &&
                            sessions_.size() < AETHON_MAX_ACTIVE_TCP_SESSION) {
                            const uint32_t ack = ntohl(tcph->ack_seq);
                            if (check_syn_cookie(key, seq - 1, ack - 1, now_ns)) {

                                if(AETHON_UNLIKELY(budget_.is_over_budget())){
                                    stats::count(stats::Event::SynDroppedMemoryPressure);
                                    return result;
                                }

                                session = new (std::nothrow) TcpStreamSession();
                                session->budget = &budget_;
                                if (AETHON_UNLIKELY(!session)) {
                                    return result;
                                }
                                session->key = key;
                                session->isn = seq - 1;
                                session->rcv_nxt = seq;
                                session->server_isn = ack - 1;
                                session->send_nxt = ack;
                                session->snd_una = ack;
                                session->state = TcpState::ESTABLISHED;
                                session->last_seen_ns = now_ns;
                                sessions_.insert(key, session);
                                result.session = session;
                                result.from_cookie = true;
                                stats::count(stats::Event::SynCookieAccepted);
                                // fall through: this segment's ACK and payload are processed normally below
                            }
                        }
                        if (!session) {
                            return result;
                        }
                    } else {
                        // Table under pressure (e.g. SYN flood): answer statelessly, allocate nothing
                        if(AETHON_UNLIKELY(sessions_.size() >= AETHON_SYNCOOKIE_THRESHOLD)){
                            result.syn_cookie = true;
                            result.syn_cookie_isn = make_syn_cookie(key, seq, now_ns);
                            stats::count(stats::Event::SynCookieSent);
                            return result;
                        }


                        // if worker memory budget exhaused refuse new syn to prevent OOM

                        if(AETHON_UNLIKELY(budget_.is_over_budget())){
                            stats::count(stats::Event::SynDroppedMemoryPressure);
                            return result;
                        }

                        // light weight session allocation only 64 bytes

                        session = new (std::nothrow) TcpStreamSession();
                        session->budget = &budget_;
                        if(AETHON_UNLIKELY(!session)){
                            return result;
                        }

                        session->key = key;
                        session->isn = seq;
                        session->rcv_nxt = seq + 1;

                        session->state = TcpState::SYN_SENT;

                        session->last_seen_ns = now_ns;

                        parse_tcp_syn_option(tcph, session->params);

                        sessions_.insert(key, session);
                        result.session = session;
                        result.is_syn = true;
                        return result;
                    }
                }

                session->last_seen_ns = now_ns;

                // RST --> connection killed by the sender
                if(AETHON_UNLIKELY(flags & TH_RST)){
                    session->state = TcpState::CLOSED;
                    result.is_closed = true;
                    delete session;
                    sessions_.erase(key);
                    result.session = nullptr;
                    return result;
                }

                // SYN Packet on an existing session lookup
                if (AETHON_UNLIKELY(flags & TH_SYN)) {
                    if (session->state == TcpState::SYN_SENT) {
                        // Legitimate duplicate handshake SYN (client retransmission before connection established)
                        result.is_syn = true;
                    } else {
                        // RFC 5961 Section 4: In-window SYN on ESTABLISHED/CLOSING connection.
                        // MUST NOT reset sequence numbers or state! Send an RFC 5961 Challenge ACK.
                        result.need_ack = true;
                    }
                    return result;
                }


                // Transition: First packet after SYN moves session to ESTABLISHED
                if (AETHON_UNLIKELY(session->state == TcpState::SYN_SENT)) {
                    if (AETHON_LIKELY(flags & TH_ACK)) {
                        session->state = TcpState::ESTABLISHED;
                        // RFC 6298: Handshake RTT measurement from SYN-ACK transmission to client ACK
                        if (session->synack_tx_time_ns > 0) {
                            uint32_t sample_ms = static_cast<uint32_t>((now_ns - session->synack_tx_time_ns) / 1000000ULL);
                            session->update_rtt(sample_ms);
                            session->synack_tx_time_ns = 0;
                        }
                    } else {
                        return result;
                    }
                }

                // If connection is not ESTABLISHED or CLOSING, ignore data
                if (AETHON_UNLIKELY(session->state != TcpState::ESTABLISHED && session->state != TcpState::CLOSING)) {
                    return result;
                }

                // Process client ACKs on established connections to slide outbound send window
                if (AETHON_LIKELY(flags & TH_ACK)) {


                    // if window size is enabled
                    const uint8_t wshift = session->params.wscale_enabled ? session->params.client_wscale : 0;
                     session->snd_wnd = static_cast<uint32_t>(ntohs(tcph->window)) << wshift;
                    parse_tcp_ack_options(tcph, session);

                    uint32_t ack_seq = ntohl(tcph->ack_seq);
                    // snd_una the oldest sequence no we transmitted that has not yet been Acked
                    if (TcpSeq::gt(ack_seq, session->snd_una) && TcpSeq::lte(ack_seq, session->send_nxt)) {
                        size_t bytes_acked = ack_seq - session->snd_una;
                        // O(1) ACK consumption: advances head pointer without O(n^2) memmove front erasure
                        session->snd_buf.consume(bytes_acked);

                        // RFC 6298 (Karn's Algorithm): Update RTT if this ACK covers the sampled sequence
                        if (session->rtt_time_ns > 0 && session->retransmit_count == 0 && TcpSeq::gte(ack_seq, session->rtt_seq)) {
                            uint32_t sample_ms = static_cast<uint32_t>((now_ns - session->rtt_time_ns) / 1000000ULL);
                            session->update_rtt(sample_ms);
                            session->rtt_time_ns = 0;
                        }

                        session->snd_una = ack_seq;
                        session->cc.on_ack(bytes_acked);
                        // Reset RTO timer and retry counter (RFC 6298 dynamic RTO)
                        session->rto_ms = (session->srtt_ms > 0)
                            ? std::min(std::max(session->srtt_ms + (session->rttvar_ms << 2), 20u), 60000u)
                            : 20u;
                        session->retransmit_count = 0;
                        session->dup_ack_count = 0;
                        session->last_tx_time_ns = now_ns;
                    } else if (ack_seq == session->snd_una && session->snd_una != session->send_nxt && payload_len == 0) {
                        // RFC 5681: Fast Retransmit on 3 duplicate ACKs
                        session->dup_ack_count++;
                        if (session->dup_ack_count == 3) {
                            session->cc.on_fast_retransmit();
                            result.fast_retransmit = true;
                        }
                    }
                }

                // process data payload

                if(AETHON_LIKELY(payload_len > 0)){
                    uint32_t cur_seq = seq;
                    const uint8_t * cur_payload = payload;
                    uint16_t cur_len = payload_len;

                    // packet completely behind rcv_nxt: a retransmission of data we already have.
                    // It MUST be ACKed: the sender retransmits because our ACK was lost, and without a
                    // new ACK it backs off exponentially until the connection stalls.

                    if(AETHON_UNLIKELY(TcpSeq::lte(cur_seq+cur_len,session->rcv_nxt))){
                        result.need_ack = true;
                        return result;
                    }

                    // partial overlap Packet starts before rcv_nxt , but end after rcv_nxt

                    if(AETHON_UNLIKELY(TcpSeq::lt(cur_seq, session->rcv_nxt))){
                        uint32_t trim = session->rcv_nxt - cur_seq;
                        cur_payload  += trim;
                        cur_len      -= trim;
                        cur_seq       = session->rcv_nxt;
                    }

                    // protect against spoofed out-of-window sequences. Checked only after the two cases
                    // above: the difference is unsigned, so data behind rcv_nxt would look 4 GB ahead.

                    if(AETHON_UNLIKELY(TcpSeq::diff(cur_seq, session->rcv_nxt) + cur_len > AETHON_TCP_WINDOW_SIZE)){
                        return result;
                    }

                    // In-order packet (packet matches rcv_nxt AND no out-of-order bytes are buffered)

                    if(AETHON_LIKELY(cur_seq == session->rcv_nxt && session->ooo_bytes == 0)){
                        result.payload     = cur_payload;
                        result.payload_len = cur_len;
                        result.is_ready    = true;
                        session->rcv_nxt  += cur_len;
                        // our of order packets (gap/hole in the sequence)
                    }else if(TcpSeq::gt(cur_seq, session->rcv_nxt)){

                        if(AETHON_LIKELY(session->init_buffers(reassembly_pool_))){
                            if (session->conflicts_with_buffered(cur_seq, cur_payload, cur_len)) {
                                result.is_closed = true;
                                result.overlap_violation = true;
                                delete session;
                                sessions_.erase(key);
                                result.session = nullptr;
                                return result;
                            }
                            session->write_ring_buffer(cur_seq, cur_payload, cur_len);
                            session->ooo_bytes += static_cast<uint32_t>(session->set_bitmap_range(cur_seq, cur_len));
                            // Duplicate ACK for rcv_nxt: lets the client fast-retransmit the missing segment
                            result.need_ack = true;
                        } else {
                            result.need_ack = true;
                        }
                    }

                    // gap - filler packet (fills the missing hole at rcv_nxt)
                    else{
                        if(AETHON_LIKELY(session->init_buffers(reassembly_pool_))){
                            if (session->conflicts_with_buffered(cur_seq, cur_payload, cur_len)) {
                                result.is_closed = true;
                                result.overlap_violation = true;
                                delete session;
                                sessions_.erase(key);
                                result.session = nullptr;
                                return result;
                            }
                            session->write_ring_buffer(cur_seq, cur_payload, cur_len);
                            session->ooo_bytes += static_cast<uint32_t>(session->set_bitmap_range(cur_seq, cur_len));

                            // drain all continuous bytes starting at rcv_next
                            size_t contiguous = session->count_continuous_bytes(session->rcv_nxt, AETHON_TCP_WINDOW_SIZE);

                            if(AETHON_LIKELY(contiguous >0 )){

                                session->read_ring_buffer(session->rcv_nxt, drain_buf_.data(), contiguous);
                                session->ooo_bytes -= static_cast<uint32_t>(session->clear_bitmap_range(session->rcv_nxt, contiguous));

                                session->rcv_nxt += contiguous;

                                result.payload = drain_buf_.data();
                                result.payload_len = contiguous;
                                result.is_ready = true;

                                if (session->ooo_bytes == 0) {
                                    session->release_buffers();
                                }
                            }
                        }
                    }

                } // end
                

                if (AETHON_UNLIKELY(flags & TH_FIN)) {
                    session->rcv_nxt++;
                    session->state = TcpState::CLOSING;
                    session->client_fin_received = true;
                    result.is_fin = true;
                    result.need_ack = true;
                }

                return result;

            }



        };

    };


};










































