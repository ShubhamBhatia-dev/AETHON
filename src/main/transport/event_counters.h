#pragma once
// Counters for rare events (resets, drops, SYN cookies, expiries) so a test run can show
// *why* connections ended. Relaxed atomics shared by all workers; never touched per packet
// on the normal path, only when the event happens.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "aethon_logger.h"

namespace aethon::stats {

enum class Event : uint8_t {
    TcpBadChecksum,       // segment dropped: TCP checksum invalid
    RstNoSession,         // RST/ACK for a segment of an unknown connection
    RstOverlapEvasion,    // retransmission conflicts with buffered data
    RstDpiMatch,          // Hyperscan rule matched (plain or decrypted)
    RstSniBlocked,        // blocked or missing SNI
    RstBadClientHello,    // ClientHello too large or invalid record length
    RstBackendFailed,     // could not hand data to the backend (buffer full, socket error)
    RstTlsError,          // TLS decrypt / protocol error
    Ja3RateLimited,       // ClientHello dropped: fingerprint over its per-worker rate limit
    SynCookieSent,        // SYN answered statelessly (table under pressure)
    SynCookieAccepted,    // connection created from a valid cookie
    SessionExpiredIdle,   // session purged after the idle timeout
    SessionRtoGiveUp,     // peer stopped acknowledging; session dropped after max retries
    SynDroppedMemoryPressure,
    SessionEvictedMemoryPressure,
    IcmpPmtuUpdate,
    IcmpForwardedToKernel,
    Count,
};

inline constexpr std::array<const char *, static_cast<size_t>(Event::Count)> kEventNames{
    "tcp_bad_checksum", "rst_no_session", "rst_overlap_evasion", "rst_dpi_match",
    "rst_sni_blocked",  "rst_bad_client_hello", "rst_backend_failed", "rst_tls_error",
    "ja3_rate_limited",
    "syn_cookie_sent",  "syn_cookie_accepted", "session_expired_idle", "session_rto_give_up",
    "syn_dropped_memory_pressure", "session_evicted_memory_pressure",
    "icmp_pmtu_update", "icmp_forwarded_to_kernel",
};

inline std::array<std::atomic<uint64_t>, static_cast<size_t>(Event::Count)> g_events{};

inline void count(Event e, const char *src_ip = nullptr, uint16_t src_port = 0,
                  const char *dst_ip = nullptr, uint16_t dst_port = 0,
                  const char *detail = nullptr) noexcept {
    g_events[static_cast<size_t>(e)].fetch_add(1, std::memory_order_relaxed);

    // Dispatch critical and security events to the asynchronous FluxIO logger
    const char *lvl = nullptr;
    const char *mod = "CORE";
    const char *act = "PASS";
    const char *msg = detail ? detail : kEventNames[static_cast<size_t>(e)];

    switch (e) {
      case Event::RstDpiMatch:
        lvl = "CRITICAL"; mod = "DPI"; act = "RESET";
        if (!detail) msg = "ATTACK DETECTED: Deep Packet Inspection (DPI) exploit signature matched - TCP RST injected";
        break;
      case Event::RstSniBlocked:
        lvl = "CRITICAL"; mod = "TLS"; act = "RESET";
        if (!detail) msg = "ATTACK DETECTED: Blacklisted TLS SNI domain intercepted - connection terminated";
        break;
      case Event::Ja3RateLimited:
        lvl = "ALERT"; mod = "TLS"; act = "DROP";
        if (!detail) msg = "ATTACK DETECTED: JA3 TLS fingerprint abuse / botnet flood - SYN dropped";
        break;
      case Event::RstOverlapEvasion:
        lvl = "CRITICAL"; mod = "TCP"; act = "RESET";
        if (!detail) msg = "ATTACK DETECTED: TCP segment overlap evasion attempt (IDS evasion attack) - session terminated";
        break;
      case Event::TcpBadChecksum:
        lvl = "WARN"; mod = "TCP"; act = "DROP";
        if (!detail) msg = "Invalid TCP checksum: segment discarded";
        break;
      case Event::SynCookieSent:
        lvl = "WARN"; mod = "TCP"; act = "COOKIE";
        if (!detail) msg = "SYN queue pressure: stateless cookie dispatched";
        break;
      case Event::SynCookieAccepted:
        lvl = "INFO"; mod = "TCP"; act = "ALLOW";
        if (!detail) msg = "SYN cookie validated: connection allowed";
        break;
      case Event::SynDroppedMemoryPressure:
        lvl = "ALERT"; mod = "MEMORY"; act = "DROP";
        if (!detail) msg = "ATTACK DETECTED: High SYN flood / memory exhaustion attack - malicious SYN dropped";
        break;
      case Event::RstBadClientHello:
        lvl = "WARN"; mod = "TLS"; act = "DROP";
        if (!detail) msg = "Malformed TLS ClientHello discarded";
        break;
      default:
        return;
    }

    if (lvl) {
      aethon::log::log_event(lvl, mod, kEventNames[static_cast<size_t>(e)],
                             src_ip ? src_ip : "0.0.0.0", src_port,
                             dst_ip ? dst_ip : "0.0.0.0", dst_port,
                             "TCP", act, msg);
    }
}

inline uint64_t get(Event e) noexcept {
    return g_events[static_cast<size_t>(e)].load(std::memory_order_relaxed);
}

// Prints "name=value" for every non-zero counter on one line. Returns false if all are zero.
inline bool print_nonzero(std::FILE *out, const char *prefix) noexcept {
    bool any = false;
    for (size_t i = 0; i < g_events.size(); ++i) {
        uint64_t v = g_events[i].load(std::memory_order_relaxed);
        if (v == 0) continue;
        if (!any) std::fprintf(out, "%s", prefix);
        std::fprintf(out, " %s=%llu", kEventNames[i], static_cast<unsigned long long>(v));
        any = true;
    }
    if (any) std::fprintf(out, "\n");
    return any;
}

inline uint64_t total() noexcept {
    uint64_t t = 0;
    for (auto &c : g_events) t += c.load(std::memory_order_relaxed);
    return t;
}

} // namespace aethon::stats
