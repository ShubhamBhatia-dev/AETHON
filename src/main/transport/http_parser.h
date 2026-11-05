#pragma once

#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <algorithm>
#include <cctype>

namespace aethon {
namespace http {

    struct ParsedHttpRequest {
        bool is_valid{false};
        std::string_view method;        // "GET", "POST", "PUT", etc.
        std::string_view raw_uri;       // Original URI e.g. "/path?arg=val"
        std::string_view path;          // Path component before '?'
        std::string_view query;         // Query string after '?'
        std::string_view version;       // "HTTP/1.1", "HTTP/1.0"
        std::string_view request_line;  // Full request line

        std::string_view host;          // Host header
        std::string_view user_agent;    // User-Agent header
        std::string_view content_type;  // Content-Type header
        std::string_view cookie;        // Cookie header
        std::string_view referer;       // Referer header
        std::string_view all_headers;   // Entire header block
        std::string_view body;          // Body payload after \r\n\r\n

        char normalized_path[1024]{};
        size_t normalized_path_len{0};

        AETHON_ALWAYS_INLINE std::string_view get_normalized_path() const noexcept {
            return std::string_view(normalized_path, normalized_path_len);
        }
    };

    class HttpParser {
    public:
        // Fast 4-byte magic integer check for common HTTP verbs
        AETHON_ALWAYS_INLINE static bool is_http_request(const uint8_t *data, size_t len) noexcept {
            if (AETHON_UNLIKELY(!data || len < 10)) return false;
            // Matches "GET " (0x20544547), "POST" (0x54534f50), "HEAD" (0x44414548), "PUT " (0x20545550)
            uint32_t magic;
            std::memcpy(&magic, data, 4);
            if (magic == 0x20544547 || magic == 0x54534f50 || magic == 0x44414548 || magic == 0x20545550) {
                return true;
            }
            // "DELETE " (0x4554454c4544)
            if (len >= 7 && std::memcmp(data, "DELETE ", 7) == 0) return true;
            // "OPTIONS" (0x4f5054494f4e)
            if (len >= 8 && std::memcmp(data, "OPTIONS ", 8) == 0) return true;
            // "PATCH "
            if (len >= 6 && std::memcmp(data, "PATCH ", 6) == 0) return true;
            return false;
        }

        static bool parse(const uint8_t *data, size_t len, ParsedHttpRequest &out) noexcept {
            if (AETHON_UNLIKELY(!data || len < 14)) return false;
            std::string_view raw(reinterpret_cast<const char *>(data), len);

            size_t first_crlf = raw.find("\r\n");
            if (AETHON_UNLIKELY(first_crlf == std::string_view::npos)) return false;
            out.request_line = raw.substr(0, first_crlf);
            size_t sp1 = out.request_line.find(' ');
            if (AETHON_UNLIKELY(sp1 == std::string_view::npos || sp1 == 0)) return false;
            out.method = out.request_line.substr(0, sp1);
            size_t sp2 = out.request_line.find(' ', sp1 + 1);
            if (AETHON_UNLIKELY(sp2 == std::string_view::npos)) return false;
            out.raw_uri = out.request_line.substr(sp1 + 1, sp2 - sp1 - 1);
            out.version = out.request_line.substr(sp2 + 1);
            size_t qmark = out.raw_uri.find('?');
            if (qmark != std::string_view::npos) {
                out.path = out.raw_uri.substr(0, qmark);
                out.query = out.raw_uri.substr(qmark + 1);
            } else {
                out.path = out.raw_uri;
                out.query = {};
            }
            normalize_url_path(out.path, out.normalized_path, sizeof(out.normalized_path), out.normalized_path_len);
            size_t header_end = raw.find("\r\n\r\n");
            if (header_end != std::string_view::npos) {
                out.all_headers = raw.substr(first_crlf + 2, header_end - (first_crlf + 2));
                out.body = raw.substr(header_end + 4);
            } else {
                out.all_headers = raw.substr(first_crlf + 2);
                out.body = {};
            }
            parse_headers(out.all_headers, out);

            out.is_valid = true;
            return true;
        }

    private:
        static void parse_headers(std::string_view h, ParsedHttpRequest &out) noexcept {
            size_t pos = 0;
            while (pos < h.size()) {
                size_t line_end = h.find("\r\n", pos);
                if (line_end == std::string_view::npos) line_end = h.size();

                std::string_view line = h.substr(pos, line_end - pos);
                pos = line_end + 2;

                size_t colon = line.find(':');
                if (colon == std::string_view::npos) continue;

                std::string_view name = line.substr(0, colon);
                std::string_view val = line.substr(colon + 1);

                while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.remove_prefix(1);
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) val.remove_suffix(1);

                if (equals_nocase(name, "host")) {
                    out.host = val;
                } else if (equals_nocase(name, "user-agent")) {
                    out.user_agent = val;
                } else if (equals_nocase(name, "content-type")) {
                    out.content_type = val;
                } else if (equals_nocase(name, "cookie")) {
                    out.cookie = val;
                } else if (equals_nocase(name, "referer")) {
                    out.referer = val;
                }
            }
        }

        static bool equals_nocase(std::string_view a, std::string_view b) noexcept {
            if (a.size() != b.size()) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) !=
                    std::tolower(static_cast<unsigned char>(b[i]))) return false;
            }
            return true;
        }

        static void normalize_url_path(std::string_view in, char *out, size_t max_out, size_t &out_len) noexcept {
            size_t o = 0;
            auto hex_val = [](char c) noexcept -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };

            for (size_t i = 0; i < in.size() && o + 1 < max_out; ++i) {
                char c = in[i];
                if (c == '%' && i + 2 < in.size()) {
                    int h1 = hex_val(in[i + 1]);
                    int h2 = hex_val(in[i + 2]);
                    if (h1 >= 0 && h2 >= 0) {
                        out[o++] = static_cast<char>((h1 << 4) | h2);
                        i += 2;
                        continue;
                    }
                }
                out[o++] = c;
            }
            out[o] = '\0';
            out_len = o;
        }
    };

} // namespace http
} // namespace aethon

