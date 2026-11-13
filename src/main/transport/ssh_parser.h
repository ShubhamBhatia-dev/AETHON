#pragma once

#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace aethon {
namespace ssh {

    struct ParsedSshBanner {
        bool is_valid{false};
        std::string_view raw_banner;      // e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        std::string_view proto_version;   // e.g. "2.0"
        std::string_view software;        // e.g. "OpenSSH_8.9p1"
        std::string_view comments;        // e.g. "Ubuntu-3ubuntu0.1" (if present)
    };

    class SshParser {
    public:
        AETHON_ALWAYS_INLINE static bool is_ssh_protocol(const uint8_t *data, size_t len) noexcept {
            if (AETHON_UNLIKELY(!data || len < 7)) return false;
            uint32_t magic;
            std::memcpy(&magic, data, 4);
            return (magic == 0x2D485353);
        }
        static bool parse_banner(const uint8_t *data, size_t len, ParsedSshBanner &out) noexcept {
            if (AETHON_UNLIKELY(!is_ssh_protocol(data, len))) return false;

            std::string_view raw(reinterpret_cast<const char *>(data), len);
            size_t end_pos = raw.find_first_of("\r\n");
            if (end_pos == std::string_view::npos) {
                if (len <= 255) {
                    end_pos = len;
                } else {
                    return false;
                }
            }

            out.raw_banner = raw.substr(0, end_pos);
            if (out.raw_banner.size() < 7 || out.raw_banner.substr(0, 4) != "SSH-") {
                return false;
            }
            size_t dash1 = 3; 
            size_t dash2 = out.raw_banner.find('-', dash1 + 1);
            if (dash2 == std::string_view::npos) {
                return false;
            }
            out.proto_version = out.raw_banner.substr(dash1 + 1, dash2 - dash1 - 1);
            std::string_view rest = out.raw_banner.substr(dash2 + 1);
            size_t sp = rest.find(' ');
            if (sp != std::string_view::npos) {
                out.software = rest.substr(0, sp);
                out.comments = rest.substr(sp + 1);
            } else {
                out.software = rest;
                out.comments = {};
            }

            out.is_valid = true;
            return true;
        }
    };

} // namespace ssh
} // namespace aethon
