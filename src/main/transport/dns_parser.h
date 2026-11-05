#pragma once

#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <arpa/inet.h>

namespace aethon {
namespace dns {

    struct DnsHeader {
        uint16_t id;       // Transaction ID
        uint16_t flags;    // Flags: QR (1 bit), Opcode (4 bits), AA, TC, RD, RA, Z, RCODE (4 bits)
        uint16_t qdcount;  // Question Count
        uint16_t ancount;  // Answer Record Count
        uint16_t nscount;  // Authority Record Count
        uint16_t arcount;  // Additional Record Count
    };

    struct ParsedDnsQuery {
        bool is_valid{false};
        uint16_t id{0};
        bool is_response{false};    // false = Query (0), true = Response (1)
        uint8_t opcode{0};          // 0 = Standard Query
        uint16_t qtype{0};          // 1 = A, 28 = AAAA, 15 = MX, 16 = TXT, 255 = ANY
        uint16_t qclass{0};         // Usually 1 (IN)
        char query_name[256]{};
        uint8_t query_name_len{0};

        AETHON_ALWAYS_INLINE std::string_view domain() const noexcept {
            return std::string_view(query_name, query_name_len);
        }
    };

    class DnsParser {
    public:
        AETHON_ALWAYS_INLINE static bool is_dns_port(uint16_t sport, uint16_t dport) noexcept {
            return (sport == 53 || dport == 53 || sport == 5353 || dport == 5353);
        }

        static bool parse_query(const uint8_t *data, size_t len, ParsedDnsQuery &out) noexcept {
            if (AETHON_UNLIKELY(!data || len < sizeof(DnsHeader) + 5)) {
                return false;
            }

            const auto *hdr = reinterpret_cast<const DnsHeader *>(data);
            out.id = ntohs(hdr->id);
            uint16_t flags = ntohs(hdr->flags);

            out.is_response = (flags & 0x8000) != 0; // QR bit (bit 15)
            out.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
            uint16_t qdcount = ntohs(hdr->qdcount);
            if (qdcount < 1) {
                return false;
            }
            size_t pos = sizeof(DnsHeader);
            size_t name_out_idx = 0;
            size_t jumps = 0;
            constexpr size_t MAX_JUMPS = 5;

            while (pos < len) {
                uint8_t label_len = data[pos];
                if (label_len == 0) {
                    pos++;
                    break;
                }
                if ((label_len & 0xC0) == 0xC0) {
                    if (pos + 1 >= len || jumps++ >= MAX_JUMPS) return false;
                    uint16_t offset = ((label_len & 0x3F) << 8) | data[pos + 1];
                    if (offset >= len) return false;
                    pos = offset;
                    continue;
                }
                if (label_len > 63 || pos + 1 + label_len > len) {
                    return false;
                }
                pos++;
                if (name_out_idx > 0 && name_out_idx < sizeof(out.query_name) - 1) {
                    out.query_name[name_out_idx++] = '.';
                }
                for (size_t i = 0; i < label_len && name_out_idx < sizeof(out.query_name) - 1; ++i) {
                    char c = static_cast<char>(data[pos + i]);
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                    out.query_name[name_out_idx++] = c;
                }

                pos += label_len;
            }

            out.query_name[name_out_idx] = '\0';
            out.query_name_len = static_cast<uint8_t>(name_out_idx);
            if (pos + 4 <= len) {
                out.qtype = (static_cast<uint16_t>(data[pos]) << 8) | static_cast<uint16_t>(data[pos + 1]);
                out.qclass = (static_cast<uint16_t>(data[pos + 2]) << 8) | static_cast<uint16_t>(data[pos + 3]);
            }

            out.is_valid = (out.query_name_len > 0);
            return out.is_valid;
        }
    };

} // namespace dns
} // namespace aethon

