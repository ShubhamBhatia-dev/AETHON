// Regression tests for TCP reassembly and the SNI domain policy (no root, no network needed).
// Feeds hand-built segments straight into TcpAssemblerEngine.
//
//   cmake --build build --target test_tcp_reassembly && ./build/src/test_tcp_reassembly
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "tcp_assembler.h"
#include "domain_blocklist.h"
#include "ip_address.h"
#include "stun_server.h"

#include <cstdio>
#include <vector>

using namespace aethon::IPv4TcpAssembler;

static int g_failures = 0;
#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) { std::printf("  PASS %s\n", msg); }                     \
        else { std::printf("  FAIL %s\n", msg); ++g_failures; }            \
    } while (0)

struct Packet {
    iphdr ip{};
    tcphdr tcp{};
};

// One client connection to 192.168.50.1:80 driven segment by segment
class Conn {
public:
    explicit Conn(uint16_t sport) : sport_(sport) {
        Packet syn = make(isn_, TH_SYN);
        engine_.process_packet(&syn.ip, &syn.tcp, nullptr, 0, tick());
        Packet ack = make(isn_ + 1, TH_ACK);
        engine_.process_packet(&ack.ip, &ack.tcp, nullptr, 0, tick());
    }

    // Send stream bytes [off, off+len) taken from data
    TcpAssemblyResult send(const std::vector<uint8_t> &data, uint32_t off, size_t len) {
        Packet p = make(isn_ + 1 + off, TH_ACK);
        return engine_.process_packet(&p.ip, &p.tcp, data.data() + off, len, tick());
    }

private:
    Packet make(uint32_t seq, uint8_t flags) const {
        Packet p;
        p.ip.ihl = 5;
        p.ip.protocol = IPPROTO_TCP;
        p.ip.saddr = inet_addr("192.168.50.2");
        p.ip.daddr = inet_addr("192.168.50.1");
        p.tcp.source = htons(sport_);
        p.tcp.dest = htons(80);
        p.tcp.seq = htonl(seq);
        p.tcp.ack_seq = htonl(1000001);
        p.tcp.doff = 5;
        p.tcp.window = htons(65535);
        reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
        return p;
    }
    uint64_t tick() { return now_ += 1000; }

    TcpAssemblerEngine engine_;
    uint16_t sport_;
    uint32_t isn_{5000};
    uint64_t now_{1'000'000'000ULL};
};

// Pseudo-random bytes (non-periodic, so data 64 KB apart differs like a real stream)
static std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    uint64_t x = 0x9E3779B97F4A7C15ULL ^ seed;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        v[i] = static_cast<uint8_t>(x);
    }
    return v;
}

// Linux retransmits a lost short segment merged with following bytes (same data, new
// boundaries). Part of the range is already buffered, part is not; the unbuffered part
// holds stale ring data from 64 KB earlier. This must NOT be treated as an attack.
static void test_resegmented_retransmission() {
    std::puts("resegmented retransmission after ring wrap-around");
    auto data = pattern(200000, 3);
    Conn c(40000);

    uint32_t off = 0;
    bool alive = true;
    while (off < 70000 && alive) {          // > 64 KB in order so the ring has wrapped
        alive = c.send(data, off, 536).session != nullptr;
        off += 536;
    }
    CHECK(alive, "70 KB in-order stream accepted");

    auto ooo = c.send(data, off + 144, 536);  // short segment [off, off+144) lost
    CHECK(ooo.session != nullptr, "out-of-order segment buffered");
    CHECK(ooo.need_ack, "out-of-order segment triggers a duplicate ACK");

    auto re = c.send(data, off, 536);         // collapsed retransmission [off, off+536)
    CHECK(re.session != nullptr, "collapsed retransmission keeps the session alive");
    CHECK(re.is_ready && re.payload_len == 144 + 536,
          "missing bytes plus buffered segment delivered in order");
}

// A real overlap evasion: the same stream bytes sent twice with different content.
static void test_conflicting_overlap_detected() {
    std::puts("conflicting overlap (evasion attempt)");
    auto a = pattern(4096, 'A');
    auto b = pattern(4096, 'B');
    Conn c(40001);

    c.send(a, 0, 536);
    c.send(a, 1000, 536);                     // hole at [536, 1000), buffered [1000, 1536)
    auto r = c.send(b, 700, 536);             // overlaps buffered bytes with different data
    CHECK(r.session == nullptr && r.is_closed, "conflicting overlap kills the session");
}

// Identical retransmission of an already buffered segment is harmless.
static void test_identical_duplicate_accepted() {
    std::puts("identical duplicate of a buffered segment");
    auto a = pattern(4096, 'C');
    Conn c(40002);

    c.send(a, 0, 536);
    c.send(a, 1000, 536);
    auto r = c.send(a, 1000, 536);
    CHECK(r.session != nullptr, "identical duplicate keeps the session alive");
}

// Two holes; the first filler only closes the first hole. Buffered data behind the second
// hole must still be tracked: it must be delivered once the second hole is filled, and its
// bitmap bits must not linger and cause a false "overlap attack" after the ring wraps.
static void test_partial_fill_keeps_tracking() {
    std::puts("partial hole fill with more out-of-order data behind it");
    auto data = pattern(300000, 11);
    Conn c(40003);

    c.send(data, 0, 536);                     // in order: rcv_nxt = 536
    c.send(data, 1608, 536);                  // buffered, holes at [536,1072) and [1072,1608)
    auto f1 = c.send(data, 536, 536);         // fills only the first hole
    CHECK(f1.is_ready && f1.payload_len == 536, "first filler delivers only up to the second hole");

    auto f2 = c.send(data, 1072, 536);        // fills the second hole
    CHECK(f2.is_ready && f2.payload_len == 1072, "second filler also delivers the buffered segment");

    // Like a real client: whatever the ACK didn't cover is retransmitted, then the stream goes on
    uint32_t off = f2.is_ready ? 1072 + f2.payload_len : 1072;
    bool alive = true;
    while (off < 1608 + 65536 - 536 && alive) {   // in order until just before one ring length later
        alive = c.send(data, off, 536).session != nullptr;
        off += 536;
    }
    // Reordering exactly over the ring positions of [1608, 2144): B arrives before A
    alive = alive && c.send(data, off + 536, 536).session != nullptr;     // B (out of order)
    alive = alive && c.send(data, off, 536).session != nullptr;           // A (fills the hole)
    CHECK(alive, "stream survives ring wrap-around after partial fills (no stale bitmap bits)");
}

// A sender retransmits data we already have when our ACK was lost. It must be ACKed again,
// and a retransmission that also carries new bytes must deliver them (it was once dropped
// silently because an unsigned window check treated "behind" as "4 GB ahead").
static void test_old_data_is_reacked() {
    std::puts("retransmission of already received data");
    auto data = pattern(8192, 77);
    Conn c(40004);

    c.send(data, 0, 536);
    c.send(data, 536, 536);                               // rcv_nxt = 1072
    auto dup = c.send(data, 0, 536);                      // fully old
    CHECK(dup.session && dup.need_ack && !dup.is_ready, "fully old segment is re-ACKed");

    auto part = c.send(data, 536, 1072);                  // [536, 1608): half old, half new
    CHECK(part.is_ready && part.payload_len == 536, "partly old segment delivers only its new bytes");
    CHECK(part.is_ready && std::memcmp(part.payload, data.data() + 1072, 536) == 0,
          "delivered bytes are the new ones");
}

// Reference RFC 1071 checksum, computed the textbook way (big-endian 16-bit words)
static uint16_t reference_tcp_checksum(uint32_t saddr_be, uint32_t daddr_be, const uint8_t *seg, size_t len) {
    uint32_t sum = 0;
    auto add16 = [&](uint16_t w) { sum += w; };
    const uint32_t s = ntohl(saddr_be), d = ntohl(daddr_be);
    add16(s >> 16); add16(s & 0xFFFF); add16(d >> 16); add16(d & 0xFFFF);
    add16(IPPROTO_TCP); add16(static_cast<uint16_t>(len));
    for (size_t i = 0; i + 1 < len; i += 2) add16(static_cast<uint16_t>(seg[i] << 8 | seg[i + 1]));
    if (len & 1) add16(static_cast<uint16_t>(seg[len - 1] << 8));
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}


static void test_tcp_window_scaling() {
    std::printf("TCP Window Scaling (RFC 7323)\n");
    TcpAssemblerEngine engine;
    uint64_t now = 1'000'000'000ULL;

    // 1. Client SYN with Window Scale Option (Kind 3, Len 3, Shift Count = 6)
    struct SynWithWscale {
        iphdr ip{};
        tcphdr tcp{};
        uint8_t opts[4]{}; // Kind 3, Len 3, Shift 6, NOP padding
    } syn_pkt;

    syn_pkt.ip.ihl = 5;
    syn_pkt.ip.saddr = inet_addr("192.168.1.50");
    syn_pkt.ip.daddr = inet_addr("192.168.1.1");
    syn_pkt.tcp.source = htons(50000);
    syn_pkt.tcp.dest = htons(443);
    syn_pkt.tcp.seq = htonl(2000);
    syn_pkt.tcp.doff = (sizeof(tcphdr) + 4) / 4;
    reinterpret_cast<uint8_t *>(&syn_pkt.tcp)[13] = TH_SYN;

    syn_pkt.opts[0] = 0x03; // TCPOPT_WINDOW
    syn_pkt.opts[1] = 0x03; // Length 3
    syn_pkt.opts[2] = 0x06; // Shift count 6 (x64)
    syn_pkt.opts[3] = 0x01; // NOP padding

    auto r_syn = engine.process_packet(&syn_pkt.ip, &syn_pkt.tcp, nullptr, 0, now);
    CHECK(r_syn.session != nullptr, "session created with window scaling");
    CHECK(r_syn.session->params.wscale_enabled, "wscale successfully negotiated");
    CHECK(r_syn.session->params.client_wscale == 6, "client shift count is 6 (64x)");
    CHECK(r_syn.session->params.server_wscale == 7, "server shift count is 7 (128x)");

    // 2. Client sends ACK with 16-bit window field = 1000
    struct AckPkt {
        iphdr ip{};
        tcphdr tcp{};
    } ack_pkt;

    ack_pkt.ip.ihl = 5;
    ack_pkt.ip.saddr = syn_pkt.ip.saddr;
    ack_pkt.ip.daddr = syn_pkt.ip.daddr;
    ack_pkt.tcp.source = syn_pkt.tcp.source;
    ack_pkt.tcp.dest = syn_pkt.tcp.dest;
    ack_pkt.tcp.seq = htonl(2001);
    ack_pkt.tcp.ack_seq = htonl(5000);
    ack_pkt.tcp.doff = 5;
    ack_pkt.tcp.window = htons(1000);
    reinterpret_cast<uint8_t *>(&ack_pkt.tcp)[13] = TH_ACK;

    engine.process_packet(&ack_pkt.ip, &ack_pkt.tcp, nullptr, 0, now += 1000);
    CHECK(r_syn.session->state == TcpState::ESTABLISHED, "session established");
    // 1000 shifted left by 6 = 64,000 bytes
    CHECK(r_syn.session->snd_wnd == 64000, "advertised window scaled by 2^6 to 64,000 bytes");

    // 3. RFC 7323 Section 2.3: Shift count > 14 clamped to 14
    struct SynExcessiveShift {
        iphdr ip{};
        tcphdr tcp{};
        uint8_t opts[4]{};
    } syn_excess;

    syn_excess.ip.ihl = 5;
    syn_excess.ip.saddr = inet_addr("192.168.1.51");
    syn_excess.ip.daddr = inet_addr("192.168.1.1");
    syn_excess.tcp.source = htons(50001);
    syn_excess.tcp.dest = htons(443);
    syn_excess.tcp.seq = htonl(3000);
    syn_excess.tcp.doff = (sizeof(tcphdr) + 4) / 4;
    reinterpret_cast<uint8_t *>(&syn_excess.tcp)[13] = TH_SYN;

    syn_excess.opts[0] = 0x03;
    syn_excess.opts[1] = 0x03;
    syn_excess.opts[2] = 18; // Illegal shift count > 14
    syn_excess.opts[3] = 0x01;

    auto r_excess = engine.process_packet(&syn_excess.ip, &syn_excess.tcp, nullptr, 0, now += 1000);
    CHECK(r_excess.session != nullptr, "session created for excessive shift");
    CHECK(r_excess.session->params.client_wscale == 14, "shift count 18 clamped to RFC maximum 14");

    // 4. Client SYN WITHOUT window scale option: stays disabled (1x)
    struct SynPlain {
        iphdr ip{};
        tcphdr tcp{};
    } syn_plain;

    syn_plain.ip.ihl = 5;
    syn_plain.ip.saddr = inet_addr("192.168.1.52");
    syn_plain.ip.daddr = inet_addr("192.168.1.1");
    syn_plain.tcp.source = htons(50002);
    syn_plain.tcp.dest = htons(443);
    syn_plain.tcp.seq = htonl(4000);
    syn_plain.tcp.doff = 5;
    reinterpret_cast<uint8_t *>(&syn_plain.tcp)[13] = TH_SYN;

    auto r_plain = engine.process_packet(&syn_plain.ip, &syn_plain.tcp, nullptr, 0, now += 1000);
    CHECK(!r_plain.session->params.wscale_enabled, "wscale disabled when option absent");

    ack_pkt.ip.saddr = syn_plain.ip.saddr;
    ack_pkt.tcp.source = syn_plain.tcp.source;
    ack_pkt.tcp.seq = htonl(4001);
    ack_pkt.tcp.window = htons(1000);
    engine.process_packet(&ack_pkt.ip, &ack_pkt.tcp, nullptr, 0, now += 1000);
    // Unscaled: exactly 1000 bytes
    CHECK(r_plain.session->snd_wnd == 1000, "unscaled window remains raw 1000 bytes");
}


static void test_tcp_checksum() {
    std::puts("TCP checksum verification");
    iphdr ip{};
    ip.saddr = inet_addr("192.168.50.2");
    ip.daddr = inet_addr("192.168.50.1");
    bool all_valid = true, all_detected = true;
    auto data = pattern(1500, 42);
    for (size_t len : {20u, 21u, 33u, 1023u, 1480u}) {          // even, odd, unaligned tails
        std::vector<uint8_t> seg(data.begin(), data.begin() + static_cast<long>(len));
        seg[16] = seg[17] = 0;                                    // checksum field
        uint16_t c = htons(reference_tcp_checksum(ip.saddr, ip.daddr, seg.data(), len));
        std::memcpy(&seg[16], &c, 2);
        all_valid &= aethon::Ipv4::is_valid_tcp_checksum(&ip, seg.data(), len);
        for (size_t bit : {size_t{5}, size_t{13 * 8 + 2}, (len - 1) * 8 + 7}) {  // seq, flags byte, last byte
            auto bad = seg;
            bad[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
            all_detected &= !aethon::Ipv4::is_valid_tcp_checksum(&ip, bad.data(), len);
        }
    }
    CHECK(all_valid, "valid segments accepted (even, odd and unaligned lengths)");
    CHECK(all_detected, "single bit flips in header and payload are rejected");
}

// Under a SYN flood the table must not fill: above the threshold SYNs get a stateless cookie,
// and only a client that echoes a valid cookie gets a session.
static void test_syn_cookies() {
    std::puts("SYN cookies under table pressure");
    TcpAssemblerEngine engine;
    uint64_t now = 5'000'000'000ULL;
    auto make_pkt = [](uint32_t src, uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags) {
        Packet p;
        p.ip.ihl = 5;
        p.ip.saddr = src;
        p.ip.daddr = inet_addr("192.168.50.1");
        p.tcp.source = htons(sport);
        p.tcp.dest = htons(443);
        p.tcp.seq = htonl(seq);
        p.tcp.ack_seq = htonl(ack);
        p.tcp.doff = 5;
        reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
        return p;
    };

    // Spoofed flood until the cookie threshold
    uint32_t n = 0;
    while (engine.session_count() < AETHON_SYNCOOKIE_THRESHOLD) {
        Packet syn = make_pkt(htonl(0x0A000000u + n), static_cast<uint16_t>(1024 + n % 60000), n * 7919u, 0, TH_SYN);
        engine.process_packet(&syn.ip, &syn.tcp, nullptr, 0, now);
        ++n;
    }
    size_t before = engine.session_count();

    const uint32_t client = inet_addr("192.168.50.2"), isn = 123456789;
    Packet syn = make_pkt(client, 50000, isn, 0, TH_SYN);
    auto r = engine.process_packet(&syn.ip, &syn.tcp, nullptr, 0, now += 1000);
    CHECK(r.syn_cookie && r.session == nullptr, "SYN above the threshold gets a cookie and no session");
    CHECK(engine.session_count() == before, "no memory allocated for the SYN");

    Packet forged = make_pkt(client, 50000, isn + 1, r.syn_cookie_isn + 2, TH_ACK);
    auto rf = engine.process_packet(&forged.ip, &forged.tcp, nullptr, 0, now += 1000);
    CHECK(rf.session == nullptr, "ACK with a wrong cookie is rejected");

    Packet other = make_pkt(client, 50001, isn + 1, r.syn_cookie_isn + 1, TH_ACK);
    auto ro = engine.process_packet(&other.ip, &other.tcp, nullptr, 0, now += 1000);
    CHECK(ro.session == nullptr, "a cookie is only valid for its own 4-tuple");

    const uint8_t hello[] = "GET / HTTP/1.1\r\n\r\n";
    Packet ack = make_pkt(client, 50000, isn + 1, r.syn_cookie_isn + 1, TH_ACK);
    auto ra = engine.process_packet(&ack.ip, &ack.tcp, hello, sizeof(hello) - 1, now += 1000);
    CHECK(ra.session && ra.from_cookie, "ACK echoing the cookie creates the session");
    CHECK(ra.is_ready && ra.payload_len == sizeof(hello) - 1, "data on the cookie ACK is delivered");
    CHECK(ra.session && ra.session->send_nxt == r.syn_cookie_isn + 1, "server sequence continues from the cookie");

    const uint8_t more[] = "more";
    Packet next = make_pkt(client, 50000, isn + 1 + sizeof(hello) - 1, r.syn_cookie_isn + 1, TH_ACK);
    auto rn = engine.process_packet(&next.ip, &next.tcp, more, 4, now += 1000);
    CHECK(rn.session == ra.session && !rn.from_cookie && rn.is_ready && rn.payload_len == 4,
          "following segments use the normal session path");
}

static void test_domain_policy() {
    std::puts("SNI domain policy");
    aethon::dns::DomainBlocklist list;
    list.add_domain("mydomain.com");
    list.add_domain("aethon.local");

    CHECK(list.is_allowed("test.local"), "unlisted domain is allowed");
    CHECK(list.is_allowed("example.com"), "unlisted .com domain is allowed");
    CHECK(!list.is_allowed("mydomain.com"), "listed domain is blocked");
    CHECK(!list.is_allowed("MyDomain.COM"), "listed domain is blocked case-insensitively");
    CHECK(!list.is_allowed("api.mydomain.com"), "subdomain of a listed domain is blocked");
    CHECK(!list.is_allowed("a.b.mydomain.com"), "deep subdomain of a listed domain is blocked");
    CHECK(list.is_allowed("notmydomain.com"), "suffix without a dot boundary is allowed");
    CHECK(!list.is_allowed(""), "empty SNI is rejected");
}

static void test_memory_budget() {
    std::puts("Worker memory budget manager");
    aethon::WorkerMemoryBudget budget(1000);
    CHECK(budget.current_bytes() == 0, "initial budget starts at 0 bytes");
    CHECK(!budget.is_over_budget(), "initial state is not over budget");
    CHECK(!budget.is_critical(), "initial state is not critical");

    budget.allocate(850);
    CHECK(budget.is_critical(), "85% allocated triggers critical watermark");
    CHECK(!budget.is_over_budget(), "85% allocated is not over budget");

    budget.allocate(150);
    CHECK(budget.is_over_budget(), "100% allocated is over budget");

    budget.deallocate(100);
    CHECK(!budget.is_over_budget(), "deallocating brings it back under budget");
    CHECK(budget.is_critical(), "90% remaining is still in critical watermark");

    budget.deallocate(600);
    CHECK(!budget.is_critical(), "30% remaining is no longer critical");

    budget.deallocate(10000);
    CHECK(budget.current_bytes() == 0, "excess deallocate clamps to zero");

    // Test engine integration with budget
    TcpAssemblerEngine engine;
    engine.memory_budget().set_max_bytes(4000);
    uint64_t now = 10'000'000'000ULL;

    auto make_pkt = [](uint32_t src, uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags) {
        Packet p;
        p.ip.ihl = 5;
        p.ip.saddr = src;
        p.ip.daddr = inet_addr("192.168.50.1");
        p.tcp.source = htons(sport);
        p.tcp.dest = htons(443);
        p.tcp.seq = htonl(seq);
        p.tcp.ack_seq = htonl(ack);
        p.tcp.doff = 5;
        reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
        return p;
    };

    const uint32_t client1 = inet_addr("192.168.50.10");
    Packet syn1 = make_pkt(client1, 40001, 1000, 0, TH_SYN);
    auto r1 = engine.process_packet(&syn1.ip, &syn1.tcp, nullptr, 0, now);
    CHECK(r1.session != nullptr, "SYN accepted under normal memory budget");
    CHECK(r1.session->recv_window() > 0, "normal receive window advertised");

    // Simulate backend buffer consumption exceeding worker budget
    engine.memory_budget().allocate(5000);
    CHECK(engine.memory_budget().is_over_budget(), "budget is now exceeded");
    CHECK(r1.session->recv_window() == 0, "zero window advertised when over budget");

    // New incoming SYN from client 2 must be refused
    uint64_t syn_dropped_before = aethon::stats::get(aethon::stats::Event::SynDroppedMemoryPressure);
    const uint32_t client2 = inet_addr("192.168.50.20");
    Packet syn2 = make_pkt(client2, 40002, 2000, 0, TH_SYN);
    auto r2 = engine.process_packet(&syn2.ip, &syn2.tcp, nullptr, 0, now += 1000);
    CHECK(r2.session == nullptr, "SYN refused when over budget");
    CHECK(aethon::stats::get(aethon::stats::Event::SynDroppedMemoryPressure) > syn_dropped_before,
          "SynDroppedMemoryPressure counter incremented");

    // Relieve memory pressure below over_budget, but keep it critical (>85%)
    engine.memory_budget().deallocate(1500); // 3500 / 4000 = 87.5%
    CHECK(!engine.memory_budget().is_over_budget(), "budget no longer over limit");
    CHECK(engine.memory_budget().is_critical(), "budget is in critical watermark (>85%)");
    CHECK(r1.session->recv_window() > 0, "receive window re-opens when under budget");

    // Now establish client 1 completely
    Packet ack1 = make_pkt(client1, 40001, 1001, 5000, TH_ACK);
    engine.process_packet(&ack1.ip, &ack1.tcp, nullptr, 0, now);

    // Idle for 6 seconds under critical memory pressure -> aggressive eviction
    uint64_t evicted_before = aethon::stats::get(aethon::stats::Event::SessionEvictedMemoryPressure);
    now += 6ULL * 1000000000ULL; // advance 6 seconds
    engine.purged_expired(now);
    CHECK(aethon::stats::get(aethon::stats::Event::SessionEvictedMemoryPressure) > evicted_before,
          "oldest idle session aggressively evicted under critical memory pressure");
    CHECK(engine.session_count() == 0, "idle session purged from table");
}

static void test_stun_server() {
    std::puts("STUN server protocol");
    using namespace aethon::stun;

    // 1. Validation test on malformed packets
    uint8_t garbage[10]{};
    CHECK(!StunServer::is_binding_request(garbage, sizeof(garbage)), "short packet rejected");

    StunHeader req{};
    req.msg_type = htons(0x0101); // response type, not request
    req.msg_length = 0;
    req.magic_cookie = htonl(StunServer::MAGIC_COOKIE);
    std::memset(req.transaction_id, 0x42, 12);
    CHECK(!StunServer::is_binding_request(reinterpret_cast<uint8_t *>(&req), sizeof(req)), "wrong message type rejected");

    req.msg_type = htons(StunServer::BINDING_REQUEST);
    req.magic_cookie = htonl(0xDEADBEEF); // wrong cookie
    CHECK(!StunServer::is_binding_request(reinterpret_cast<uint8_t *>(&req), sizeof(req)), "wrong magic cookie rejected");

    // 2. Valid request
    req.magic_cookie = htonl(StunServer::MAGIC_COOKIE);
    CHECK(StunServer::is_binding_request(reinterpret_cast<uint8_t *>(&req), sizeof(req)), "valid binding request accepted");

    // 3. Response construction
    uint8_t resp_buf[64]{};
    uint32_t client_ip = inet_addr("203.0.113.195");
    uint16_t client_port = htons(54321);

    size_t resp_len = StunServer::build_response(
        reinterpret_cast<uint8_t *>(&req), sizeof(req), client_ip, client_port, resp_buf, sizeof(resp_buf));
    
    CHECK(resp_len == StunServer::RESPONSE_SIZE, "response size is exactly 32 bytes");

    const auto *resp_hdr = reinterpret_cast<const StunHeader *>(resp_buf);
    CHECK(ntohs(resp_hdr->msg_type) == StunServer::BINDING_RESPONSE, "response message type is 0x0101");
    CHECK(ntohs(resp_hdr->msg_length) == sizeof(StunXorMappedAddress), "attribute length matches");
    CHECK(ntohl(resp_hdr->magic_cookie) == StunServer::MAGIC_COOKIE, "response echoes magic cookie");
    CHECK(std::memcmp(resp_hdr->transaction_id, req.transaction_id, 12) == 0, "transaction ID echoed byte-for-byte");

    const auto *attr = reinterpret_cast<const StunXorMappedAddress *>(resp_buf + sizeof(StunHeader));
    CHECK(ntohs(attr->attr_type) == StunServer::ATTR_XOR_MAPPED_ADDRESS, "attribute type is XOR-MAPPED-ADDRESS (0x0020)");
    CHECK(attr->family == 0x01, "address family is IPv4");

    // Un-XOR the port and IP to verify correctness:
    uint16_t unxored_port = attr->x_port ^ htons(static_cast<uint16_t>(StunServer::MAGIC_COOKIE >> 16));
    uint32_t unxored_ip = attr->x_ip ^ htonl(StunServer::MAGIC_COOKIE);

    CHECK(unxored_port == client_port, "XOR port decodes to original client port");
    CHECK(unxored_ip == client_ip, "XOR IP decodes to original client IP");
}

static void test_tcp_sack() {
    std::puts("TCP SACK (Selective Acknowledgment)");
    TcpAssemblerEngine engine;
    uint64_t now = 20'000'000'000ULL;

    // 1. Client SYN with SACK-Permitted option (Kind 4, Length 2)
    struct SynWithSack {
        iphdr ip{};
        tcphdr tcp{};
        uint8_t opts[4]{0x04, 0x02, 0x01, 0x01}; // Kind 4, Len 2 + 2 NOPs
    } syn_pkt;

    syn_pkt.ip.ihl = 5;
    syn_pkt.ip.saddr = inet_addr("192.168.50.30");
    syn_pkt.ip.daddr = inet_addr("192.168.50.1");
    syn_pkt.tcp.source = htons(55555);
    syn_pkt.tcp.dest = htons(443);
    syn_pkt.tcp.seq = htonl(1000);
    syn_pkt.tcp.doff = (sizeof(tcphdr) + 4) / 4;
    reinterpret_cast<uint8_t *>(&syn_pkt.tcp)[13] = TH_SYN;

    auto r_syn = engine.process_packet(&syn_pkt.ip, &syn_pkt.tcp, nullptr, 0, now);
    CHECK(r_syn.session != nullptr, "SYN with SACK-Permitted accepted");
    CHECK(r_syn.session->params.sack_permitted, "SACK negotiated successfully in session params");

    // 2. Client ACK to complete 3-way handshake
    struct AckPkt {
        iphdr ip{};
        tcphdr tcp{};
    } ack_pkt;

    ack_pkt.ip.ihl = 5;
    ack_pkt.ip.saddr = syn_pkt.ip.saddr;
    ack_pkt.ip.daddr = syn_pkt.ip.daddr;
    ack_pkt.tcp.source = syn_pkt.tcp.source;
    ack_pkt.tcp.dest = syn_pkt.tcp.dest;
    ack_pkt.tcp.seq = htonl(1001);
    ack_pkt.tcp.ack_seq = htonl(5000);
    ack_pkt.tcp.doff = 5;
    reinterpret_cast<uint8_t *>(&ack_pkt.tcp)[13] = TH_ACK;

    engine.process_packet(&ack_pkt.ip, &ack_pkt.tcp, nullptr, 0, now += 1000);
    CHECK(r_syn.session->state == TcpState::ESTABLISHED, "session established");

    // 3. Client sends duplicate ACK with SACK Option Kind 5 reporting received block [6000, 8000)
    struct AckWithSack {
        iphdr ip{};
        tcphdr tcp{};
        uint8_t opts[12]{}; // NOP, NOP, Kind 5, Len 10, left (4B), right (4B)
    } sack_pkt;

    sack_pkt.ip.ihl = 5;
    sack_pkt.ip.saddr = syn_pkt.ip.saddr;
    sack_pkt.ip.daddr = syn_pkt.ip.daddr;
    sack_pkt.tcp.source = syn_pkt.tcp.source;
    sack_pkt.tcp.dest = syn_pkt.tcp.dest;
    sack_pkt.tcp.seq = htonl(1001);
    sack_pkt.tcp.ack_seq = htonl(5000); // still asking for 5000
    sack_pkt.tcp.doff = (sizeof(tcphdr) + 12) / 4;
    reinterpret_cast<uint8_t *>(&sack_pkt.tcp)[13] = TH_ACK;

    sack_pkt.opts[0] = 0x01; // NOP
    sack_pkt.opts[1] = 0x01; // NOP
    sack_pkt.opts[2] = 0x05; // Kind 5: SACK
    sack_pkt.opts[3] = 0x0A; // Length 10 (2 + 8)
    uint32_t left = htonl(6000);
    uint32_t right = htonl(8000);
    std::memcpy(&sack_pkt.opts[4], &left, 4);
    std::memcpy(&sack_pkt.opts[8], &right, 4);

    engine.process_packet(&sack_pkt.ip, &sack_pkt.tcp, nullptr, 0, now += 1000);

    CHECK(r_syn.session->num_sack_blocks == 1, "parsed exactly 1 SACK block");
    CHECK(r_syn.session->client_sack_blocks[0].left_edge == 6000, "SACK block left edge is 6000");
    CHECK(r_syn.session->client_sack_blocks[0].right_edge == 8000, "SACK block right edge is 8000");

    // 4. Test is_sacked() membership
    CHECK(!r_syn.session->is_sacked(5000), "seq 5000 is missing (not sacked)");
    CHECK(!r_syn.session->is_sacked(5999), "seq 5999 is missing (not sacked)");
    CHECK(r_syn.session->is_sacked(6000), "seq 6000 is marked sacked");
    CHECK(r_syn.session->is_sacked(7000), "seq 7000 is marked sacked");
    CHECK(r_syn.session->is_sacked(7999), "seq 7999 is marked sacked");
    CHECK(!r_syn.session->is_sacked(8000), "seq 8000 is beyond right edge (not sacked)");
}

static void test_icmp_pmtu_discovery() {
    std::printf("ICMP Path-MTU Discovery (RFC 1191)\n");
    TcpAssemblerEngine engine;
    uint64_t now = 1'000'000'000ULL;

    struct SynPkt {
        iphdr ip{};
        tcphdr tcp{};
    } syn_pkt;

    syn_pkt.ip.ihl = 5;
    syn_pkt.ip.saddr = inet_addr("10.0.0.99");
    syn_pkt.ip.daddr = inet_addr("10.0.0.1");
    syn_pkt.tcp.source = htons(49152);
    syn_pkt.tcp.dest = htons(443);
    syn_pkt.tcp.seq = htonl(1000);
    syn_pkt.tcp.doff = 5;
    reinterpret_cast<uint8_t *>(&syn_pkt.tcp)[13] = TH_SYN;

    auto r_syn = engine.process_packet(&syn_pkt.ip, &syn_pkt.tcp, nullptr, 0, now);
    CHECK(r_syn.session != nullptr, "session created for PMTU test");
    CHECK(r_syn.session->params.mss == 1460, "initial MSS is standard 1460");

    // Establish the session
    struct AckPkt {
        iphdr ip{};
        tcphdr tcp{};
    } ack_pkt;

    ack_pkt.ip.ihl = 5;
    ack_pkt.ip.saddr = syn_pkt.ip.saddr;
    ack_pkt.ip.daddr = syn_pkt.ip.daddr;
    ack_pkt.tcp.source = syn_pkt.tcp.source;
    ack_pkt.tcp.dest = syn_pkt.tcp.dest;
    ack_pkt.tcp.seq = htonl(1001);
    ack_pkt.tcp.ack_seq = htonl(5000);
    ack_pkt.tcp.doff = 5;
    reinterpret_cast<uint8_t *>(&ack_pkt.tcp)[13] = TH_ACK;

    engine.process_packet(&ack_pkt.ip, &ack_pkt.tcp, nullptr, 0, now += 1000);
    CHECK(r_syn.session->state == TcpState::ESTABLISHED, "session established for PMTU test");

    // 1. Simulate router returning ICMP Type 3 Code 4 with Next-Hop MTU = 1420 (PPPoE / GRE tunnel)
    bool pmtu_handled = engine.handle_icmp_pmtu(
        syn_pkt.ip.saddr, syn_pkt.tcp.source,
        syn_pkt.ip.daddr, syn_pkt.tcp.dest,
        1420);
    CHECK(pmtu_handled, "PMTU update successfully processed for active session");
    CHECK(r_syn.session->params.mss == 1380, "MSS reduced from 1460 to 1380 (1420 - 40B)");
    CHECK(r_syn.session->cc.mss == 1380, "congestion control MSS updated to 1380");
    CHECK(r_syn.session->cc.cwnd == 1380, "cwnd reset to 1 MSS for fast congestion recovery");

    // 2. Next intermediate tunnel bottleneck with MTU = 1280
    pmtu_handled = engine.handle_icmp_pmtu(
        syn_pkt.ip.saddr, syn_pkt.tcp.source,
        syn_pkt.ip.daddr, syn_pkt.tcp.dest,
        1280);
    CHECK(pmtu_handled, "second PMTU update processed");
    CHECK(r_syn.session->params.mss == 1240, "MSS reduced to 1240 (1280 - 40B)");

    // 3. Low MTU clamped to RFC minimum IPv4 MSS (536 bytes)
    pmtu_handled = engine.handle_icmp_pmtu(
        syn_pkt.ip.saddr, syn_pkt.tcp.source,
        syn_pkt.ip.daddr, syn_pkt.tcp.dest,
        300);
    CHECK(pmtu_handled, "clamped PMTU update processed");
    CHECK(r_syn.session->params.mss == 536, "MSS clamped to minimum 536 bytes");

    // 4. ICMP PMTU for non-existent flow returns false
    bool unknown_flow = engine.handle_icmp_pmtu(
        inet_addr("192.168.1.1"), htons(1234),
        syn_pkt.ip.daddr, syn_pkt.tcp.dest,
        1400);
    CHECK(!unknown_flow, "PMTU for non-existent session ignored");
}

int main() {
    test_resegmented_retransmission();
    test_conflicting_overlap_detected();
    test_identical_duplicate_accepted();
    test_partial_fill_keeps_tracking();
    test_old_data_is_reacked();
    test_tcp_checksum();
    test_syn_cookies();
    test_domain_policy();
    test_memory_budget();
    test_stun_server();
    test_tcp_sack();
    test_icmp_pmtu_discovery();
    test_tcp_window_scaling();

    
    std::printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
