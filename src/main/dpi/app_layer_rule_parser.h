#pragma once

#include "rule_parser.h"
#include <string_view>
#include <vector>
#include <unordered_map>
#include <optional>
#include <string>
#include <cstdint>
#include <algorithm>

namespace aethon {
namespace dpi {

    // Identifies which protocol or sticky buffer a pattern is targeting
    enum class AppBufferType : uint8_t {
        RAW_STREAM = 0,     // Default TCP/UDP raw payload
        // HTTP Request buffers
        HTTP_METHOD,        // http.method (GET, POST, etc.)
        HTTP_URI,           // http.uri, http_uri (/index.php?id=1)
        HTTP_RAW_URI,       // http.uri.raw, http_raw_uri
        HTTP_HOST,          // http.host, http_host
        HTTP_USER_AGENT,    // http.user_agent, http_user_agent
        HTTP_HEADER,        // http.header, http_header
        HTTP_RAW_HEADER,    // http.header.raw, http_raw_header
        HTTP_REQUEST_BODY,  // http.request_body, http_client_body
        HTTP_COOKIE,        // http.cookie, http_cookie
        HTTP_REQUEST_LINE,  // http.request_line
        HTTP_CONTENT_TYPE,  // http.content_type
        // DNS buffers
        DNS_QUERY_NAME,     // dns.query (e.g. evil.domain.com)
        // TLS buffers
        TLS_SNI,            // tls.sni (Server Name Indication)
        TLS_CERT_SUBJECT,   // tls.cert_subject
        TLS_CERT_ISSUER,    // tls.cert_issuer
        TLS_JA3_HASH        // ja3.hash / ja3s.hash
    };

    struct AppLayerPattern {
        AppBufferType buffer{AppBufferType::RAW_STREAM};
        std::string pattern;          // Regex / normalized string for Hyperscan
        std::string literal_bytes;    // Exact unescaped byte sequence
        bool nocase{false};
        bool is_negated{false};
        bool startswith{false};       // ^ anchor on this buffer
        bool endswith{false};         // $ anchor on this buffer
        int32_t depth{-1};
        int32_t offset{-1};
        int32_t distance{-1};
        int32_t within{-1};
        int32_t bsize{-1};            // Buffer size constraint (bsize:N)
    };

    struct AppLayerRule {
        uint32_t sid{0};
        uint32_t rev{1};
        rules::RuleAction action{rules::RuleAction::ALERT};
        rules::RuleProtocol protocol{rules::RuleProtocol::ANY};
        rules::PortRange src_port{};
        rules::PortRange dst_port{};
        bool flow_to_server{false};
        bool flow_established{false};

        // Multi-buffer patterns: allows matching e.g. http.method=="POST" AND http.uri=="/login"
        std::vector<AppLayerPattern> patterns;
        std::string pcre_regex;
        bool has_pcre{false};
        bool pcre_nocase{false};

        std::string msg;
        std::string classtype;
        std::string cve;
        std::string severity;
        bool block{true};
    };

    // Parsed HTTP Request Representation (zero-copy string_views)
    struct ParsedHttpRequest {
        std::string_view method;
        std::string_view uri;
        std::string_view raw_uri;
        std::string_view host;
        std::string_view user_agent;
        std::string_view headers;
        std::string_view body;
        std::string_view cookie;
        std::string_view content_type;
        std::string_view request_line;

        AETHON_ALWAYS_INLINE std::string_view get_buffer(AppBufferType type) const noexcept {
            switch (type) {
                case AppBufferType::HTTP_METHOD:       return method;
                case AppBufferType::HTTP_URI:          return uri;
                case AppBufferType::HTTP_RAW_URI:      return raw_uri.empty() ? uri : raw_uri;
                case AppBufferType::HTTP_HOST:         return host;
                case AppBufferType::HTTP_USER_AGENT:   return user_agent;
                case AppBufferType::HTTP_HEADER:
                case AppBufferType::HTTP_RAW_HEADER:   return headers;
                case AppBufferType::HTTP_REQUEST_BODY: return body;
                case AppBufferType::HTTP_COOKIE:       return cookie;
                case AppBufferType::HTTP_CONTENT_TYPE: return content_type;
                case AppBufferType::HTTP_REQUEST_LINE: return request_line;
                default: return {};
            }
        }
    };

    // Fast zero-allocation HTTP/1.x stream parser
    class FastHttpParser {
    public:
        static bool parse_request(const uint8_t *data, size_t len, ParsedHttpRequest &out) noexcept {
            if (!data || len < 10) return false;
            std::string_view raw(reinterpret_cast<const char*>(data), len);

            // 1. Request Line: METHOD URI HTTP/1.x\r\n
            size_t first_crlf = raw.find("\r\n");
            if (first_crlf == std::string_view::npos) return false;
            std::string_view line = raw.substr(0, first_crlf);
            out.request_line = line;

            size_t sp1 = line.find(' ');
            if (sp1 == std::string_view::npos) return false;
            out.method = line.substr(0, sp1);

            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string_view::npos) return false;
            out.uri = line.substr(sp1 + 1, sp2 - sp1 - 1);
            out.raw_uri = out.uri;

            // 2. Separate Headers and Body (\r\n\r\n)
            size_t header_end = raw.find("\r\n\r\n");
            if (header_end != std::string_view::npos) {
                out.headers = raw.substr(first_crlf + 2, header_end - (first_crlf + 2));
                out.body = raw.substr(header_end + 4);
            } else {
                out.headers = raw.substr(first_crlf + 2);
                out.body = {};
            }

            // 3. Scan Common Headers (Case-insensitive matching)
            parse_headers(out.headers, out);
            return true;
        }

    private:
        static void parse_headers(std::string_view h, ParsedHttpRequest &out) noexcept {
            size_t pos = 0;
            while (pos < h.size()) {
                size_t line_end = h.find("\r\n", pos);
                if (line_end == std::string_view::npos) line_end = h.size();

                std::string_view header_line = h.substr(pos, line_end - pos);
                pos = line_end + 2;

                size_t colon = header_line.find(':');
                if (colon == std::string_view::npos) continue;

                std::string_view name = header_line.substr(0, colon);
                std::string_view val = header_line.substr(colon + 1);

                // Trim leading spaces
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.remove_prefix(1);

                if (equals_nocase(name, "host")) {
                    out.host = val;
                } else if (equals_nocase(name, "user-agent")) {
                    out.user_agent = val;
                } else if (equals_nocase(name, "cookie")) {
                    out.cookie = val;
                } else if (equals_nocase(name, "content-type")) {
                    out.content_type = val;
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
    };

    // Parser for Application-Layer Suricata/Snort Rules
    class AppLayerRuleParser {
    public:
        static std::optional<AppLayerRule> parse_rule(std::string_view line) {
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
            if (line.empty() || line.front() == '#') return std::nullopt;

            size_t opt_start = line.find('(');
            size_t opt_end   = line.rfind(')');
            if (opt_start == std::string_view::npos || opt_end == std::string_view::npos || opt_start >= opt_end) {
                return std::nullopt;
            }

            std::string_view header_str = line.substr(0, opt_start);
            std::string_view body_str   = line.substr(opt_start + 1, opt_end - opt_start - 1);

            // Tokenize Header
            std::vector<std::string_view> tokens;
            size_t p = 0;
            while (p < header_str.size()) {
                while (p < header_str.size() && (header_str[p] == ' ' || header_str[p] == '\t')) ++p;
                if (p >= header_str.size()) break;
                size_t s = p;
                while (p < header_str.size() && header_str[p] != ' ' && header_str[p] != '\t') ++p;
                tokens.push_back(header_str.substr(s, p - s));
            }
            if (tokens.size() < 7) return std::nullopt;

            AppLayerRule rule;
            if (tokens[0] == "alert")       rule.action = rules::RuleAction::ALERT;
            else if (tokens[0] == "drop")   rule.action = rules::RuleAction::DROP;
            else if (tokens[0] == "reject") rule.action = rules::RuleAction::REJECT;
            else if (tokens[0] == "pass")   rule.action = rules::RuleAction::PASS;
            else return std::nullopt;

            if (tokens[1] == "http" || tokens[1] == "http1") rule.protocol = rules::RuleProtocol::TCP;
            else if (tokens[1] == "dns") rule.protocol = rules::RuleProtocol::UDP;
            else if (tokens[1] == "tls") rule.protocol = rules::RuleProtocol::TCP;
            else if (tokens[1] == "tcp") rule.protocol = rules::RuleProtocol::TCP;
            else if (tokens[1] == "udp") rule.protocol = rules::RuleProtocol::UDP;

            rule.src_port = rules::parse_port_range(tokens[3]);
            rule.dst_port = rules::parse_port_range(tokens[6]);

            // Parse Options & Sticky Buffers
            AppBufferType current_buffer = AppBufferType::RAW_STREAM;
            int32_t current_bsize = -1;
            size_t bpos = 0;

            while (bpos < body_str.size()) {
                while (bpos < body_str.size() && (body_str[bpos] == ' ' || body_str[bpos] == '\t' || body_str[bpos] == ';')) ++bpos;
                if (bpos >= body_str.size()) break;

                size_t semi = bpos;
                bool in_quote = false;
                while (semi < body_str.size()) {
                    if (body_str[semi] == '"' && (semi == 0 || body_str[semi - 1] != '\\')) {
                        in_quote = !in_quote;
                    } else if (body_str[semi] == ';' && !in_quote) {
                        break;
                    }
                    ++semi;
                }

                std::string_view opt = body_str.substr(bpos, semi - bpos);
                bpos = semi + 1;
                while (!opt.empty() && (opt.front() == ' ' || opt.front() == '\t')) opt.remove_prefix(1);
                while (!opt.empty() && (opt.back() == ' ' || opt.back() == '\t')) opt.remove_suffix(1);
                if (opt.empty()) continue;

                size_t colon = opt.find(':');
                std::string_view key = (colon == std::string_view::npos) ? opt : opt.substr(0, colon);
                std::string_view val = (colon == std::string_view::npos) ? std::string_view{} : opt.substr(colon + 1);

                while (!key.empty() && key.back() == ' ') key.remove_suffix(1);
                while (!val.empty() && val.front() == ' ') val.remove_prefix(1);

                auto unquote = [](std::string_view v) noexcept -> std::string_view {
                    if (v.size() >= 2 && v.front() == '"' && v.back() == '"') return v.substr(1, v.size() - 2);
                    return v;
                };

                // Check for Sticky Buffer Keywords
                if (key == "http.uri" || key == "http_uri")            { current_buffer = AppBufferType::HTTP_URI; continue; }
                if (key == "http.uri.raw" || key == "http_raw_uri")    { current_buffer = AppBufferType::HTTP_RAW_URI; continue; }
                if (key == "http.method" || key == "http_method")      { current_buffer = AppBufferType::HTTP_METHOD; continue; }
                if (key == "http.host" || key == "http_host")          { current_buffer = AppBufferType::HTTP_HOST; continue; }
                if (key == "http.user_agent" || key == "http_user_agent") { current_buffer = AppBufferType::HTTP_USER_AGENT; continue; }
                if (key == "http.header" || key == "http_header")      { current_buffer = AppBufferType::HTTP_HEADER; continue; }
                if (key == "http.header.raw" || key == "http_raw_header") { current_buffer = AppBufferType::HTTP_RAW_HEADER; continue; }
                if (key == "http.request_body" || key == "http_client_body") { current_buffer = AppBufferType::HTTP_REQUEST_BODY; continue; }
                if (key == "http.cookie" || key == "http_cookie")      { current_buffer = AppBufferType::HTTP_COOKIE; continue; }
                if (key == "http.request_line")                        { current_buffer = AppBufferType::HTTP_REQUEST_LINE; continue; }
                if (key == "dns.query")                                { current_buffer = AppBufferType::DNS_QUERY_NAME; continue; }
                if (key == "tls.sni")                                  { current_buffer = AppBufferType::TLS_SNI; continue; }
                if (key == "pkt_data" || key == "raw")                 { current_buffer = AppBufferType::RAW_STREAM; continue; }

                // Modifiers on the current pattern
                if (key == "content") {
                    AppLayerPattern pat;
                    pat.buffer = current_buffer;
                    pat.bsize = current_bsize;
                    current_bsize = -1; // reset after assigning to pattern
                    if (!val.empty() && val.front() == '!') {
                        pat.is_negated = true;
                        val.remove_prefix(1);
                    }
                    std::string_view raw_val = unquote(val);
                    pat.pattern = rules::normalize_content_to_regex(raw_val);
                    pat.literal_bytes = rules::decode_content_bytes(raw_val);
                    rule.patterns.push_back(std::move(pat));
                } else if (key == "nocase" && !rule.patterns.empty()) {
                    rule.patterns.back().nocase = true;
                } else if (key == "startswith" && !rule.patterns.empty()) {
                    rule.patterns.back().startswith = true;
                } else if (key == "endswith" && !rule.patterns.empty()) {
                    rule.patterns.back().endswith = true;
                } else if (key == "depth" && !rule.patterns.empty()) {
                    int32_t d = -1;
                    std::from_chars(val.data(), val.data() + val.size(), d);
                    rule.patterns.back().depth = d;
                } else if (key == "offset" && !rule.patterns.empty()) {
                    int32_t o = -1;
                    std::from_chars(val.data(), val.data() + val.size(), o);
                    rule.patterns.back().offset = o;
                } else if (key == "bsize") {
                    int32_t b = -1;
                    std::from_chars(val.data(), val.data() + val.size(), b);
                    current_bsize = b;
                    if (!rule.patterns.empty() && rule.patterns.back().buffer == current_buffer) {
                        rule.patterns.back().bsize = b;
                    }
                } else if (key == "msg") {
                    rule.msg = std::string(unquote(val));
                } else if (key == "sid") {
                    uint32_t s = 0;
                    std::from_chars(val.data(), val.data() + val.size(), s);
                    rule.sid = s;
                } else if (key == "rev") {
                    uint32_t r = 1;
                    std::from_chars(val.data(), val.data() + val.size(), r);
                    rule.rev = r;
                } else if (key == "classtype") {
                    rule.classtype = std::string(val);
                } else if (key == "pcre") {
                    std::string_view raw_pcre = unquote(val);
                    if (raw_pcre.size() >= 2 && raw_pcre.front() == '/') {
                        size_t last_slash = raw_pcre.rfind('/');
                        if (last_slash != std::string_view::npos && last_slash > 0) {
                            rule.pcre_regex = std::string(raw_pcre.substr(1, last_slash - 1));
                            rule.has_pcre = true;
                            rule.pcre_nocase = raw_pcre.substr(last_slash + 1).find('i') != std::string_view::npos;
                        }
                    }
                }
            }

            if (rule.sid == 0 || (rule.patterns.empty() && !rule.has_pcre)) {
                return std::nullopt;
            }
            return rule;
        }
    };

} // namespace dpi
} // namespace aethon
