#pragma once

#include <cstddef>
#include <cstdint>

namespace aethon {
namespace config {

namespace tcp {
    // MSS & MTU Defaults (RFC 879, RFC 1191)
    inline constexpr size_t DEFAULT_MSS = 1460;
    inline constexpr size_t MIN_IPV4_MSS = 536;
    inline constexpr size_t MIN_IPV4_MTU = 576;

    // Window Scaling & Flow Control (RFC 7323)
    // Server window scale factor: 7 -> 2^7 = 128 multiplier (~8.4 MB max window)
    inline constexpr uint8_t DEFAULT_SERVER_WSCALE = 7;
    // Maximum allowable shift per RFC 7323 (shifts > 14 are clamped)
    inline constexpr uint8_t MAX_WSCALE_SHIFT = 14;
    inline constexpr size_t DEFAULT_WINDOW_SIZE = 65535;
    inline constexpr size_t TCP_WINDOW_SIZE = 65536;
    inline constexpr size_t TCP_BITMAP_WORDS = TCP_WINDOW_SIZE / 64;

    // Capacity & Flow Buffers
    inline constexpr size_t MAX_ACTIVE_TCP_SESSION = 65536;
    inline constexpr size_t SYNCOOKIE_THRESHOLD = MAX_ACTIVE_TCP_SESSION / 4;
    inline constexpr size_t MAX_BACKEND_BUF = 1024 * 1024; // 1 MB
    inline constexpr size_t MAX_SND_BUF = 1024 * 1024;     // 1 MB
    inline constexpr size_t BACKEND_BATCH_SIZE = 32;
    inline constexpr size_t MAX_CLIENT_HELLO = 16384 + 5;
    inline constexpr size_t TLS_SLACK = 1024;

    // Reliability & State Timeouts (RFC 6298)
    inline constexpr uint64_t SYN_TIMEOUT_NS = 3ULL * 1'000'000'000ULL;        // 3 seconds
    inline constexpr uint64_t ESTAB_TIMEOUT_NS = 120ULL * 1'000'000'000ULL;    // 120 seconds keepalive
    inline constexpr uint64_t TIMEWAIT_TIMEOUT_NS = 2ULL * 1'000'000'000ULL;   // 2 seconds TIME_WAIT for wire-speed churn recovery
    inline constexpr uint64_t COOKIE_SLOT_NS = 64ULL * 1'000'000'000ULL;       // 64 second time slots
    inline constexpr uint32_t INITIAL_RTO_MS = 1000;                           // 1 second initial RTO
    inline constexpr uint8_t MAX_TCP_RETRIES = 8;
    inline constexpr size_t MAX_SACK_BLOCKS = 4;                               // RFC 2018 max SACK blocks

    // Congestion Control (RFC 5681, RFC 6928)
    inline constexpr uint32_t INITIAL_CWND_SEGMENTS = 32;                     // initcwnd = 32 MSS (~46 KB) for low-latency line-rate transfers
}

namespace udp {
    inline constexpr size_t MAX_IP_DATAGRAM_SIZE = 65536;
    inline constexpr size_t MAX_ACTIVE_DGRAM_SESSIONS = 1024;
    inline constexpr size_t MAX_FRAGMENTS_PER_ID = 64;
    inline constexpr size_t REASSEMBLY_TIMEOUT_SEC = 30;
    inline constexpr uint64_t REASSEMBLY_TIMEOUT_NS = static_cast<uint64_t>(REASSEMBLY_TIMEOUT_SEC) * 1'000'000'000ULL;
}

namespace memory {
    inline constexpr size_t DEFAULT_WORKER_BUDGET = 256 * 1024 * 1024; // 256 MB per worker fallback
    inline constexpr size_t MIN_BUDGET_BYTES = 64 * 1024 * 1024;        // 64 MB minimum
    inline constexpr double HOST_RAM_PERCENTAGE = 0.40;                // 40% of host RAM
    inline constexpr size_t CRITICAL_WATERMARK_PCT = 85;               // 85% RAM watermark
    inline constexpr size_t UNMASK_SLACK_BYTES = 64 * 1024;            // 64 KB hysteresis slack
    inline constexpr uint64_t CRITICAL_EVICTION_AGE_NS = 5ULL * 1'000'000'000ULL; // 5 sec idle eviction limit
}

namespace net {
    inline constexpr const char* DEFAULT_TAP_NAME = "aethon0";
    inline constexpr uint16_t STUN_DEFAULT_PORT = 3478;
    inline constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;
    inline constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
    inline constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;
    inline constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

    // AF_XDP UMEM and Ring Defaults
    inline constexpr size_t DEFAULT_NUM_FRAMES = 16384;
    inline constexpr size_t DEFAULT_FRAME_SIZE = 2048;
    inline constexpr size_t DEFAULT_RING_SIZE = 2048;
    inline constexpr size_t DEFAULT_MAX_QUEUES = 64;
    inline constexpr size_t DEFAULT_FALLBACK_CAPACITY = 8192;
    inline constexpr size_t DEFAULT_BATCH_SIZE = 64;
    inline constexpr uint32_t DEFAULT_SPIN_LIMIT = 2048;
    inline constexpr const char* DEFAULT_BPF_PIN_DIR = "/sys/fs/bpf/aethon";
}

namespace tls {
    inline constexpr size_t MAX_SERVICES = 256;
    inline constexpr uint8_t RECORD_HANDSHAKE = 0x16;
    inline constexpr uint8_t RECORD_APPLICATION_DATA = 0x17;
    inline constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    inline constexpr uint16_t EXT_SERVER_NAME = 0x0000;
    inline constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000A;
    inline constexpr uint16_t EXT_EC_POINT_FORMATS = 0x000B;
    inline constexpr uint8_t SNI_HOST_NAME = 0x00;
    inline constexpr int MAX_JA3_HASH_STRING = 2000;
    inline constexpr uint8_t JA3_RATE_LIMIT_SAMPLES = 8;
    inline constexpr size_t JA3_MAX_FINGERPRINTS = 4000;
}

namespace system {
    inline constexpr uint32_t WATCHDOG_INTERVAL_SEC = 1;
    inline constexpr uint32_t WATCHDOG_TIMEOUT_SEC = 5;
    inline constexpr int TELEMETRY_CPU_CORE = 0;
}

namespace http {
    inline constexpr char HTTP_502_BAD_GATEWAY[] =
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Server: Aethon-Gateway\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 269\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>502 Bad Gateway</title></head>\n"
        "<body style=\"font-family:sans-serif;text-align:center;padding:50px;\">\n"
        "  <h1 style=\"color:#e53e3e;\">502 Bad Gateway</h1>\n"
        "  <p>The upstream backend service is currently unreachable.</p>\n"
        "</body>\n"
        "</html>\n";
}

} // namespace config
} // namespace aethon
