#pragma once
#include "aethon/aethon.h"
#include "config/constants.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>

namespace aethon::stun {
    #pragma pack(push ,1)
    struct StunHeader {
        uint16_t msg_type;           // 0x0001 (Request), 0x0101 (Success Response)
        uint16_t msg_length;         // Length of attributes following header
        uint32_t magic_cookie;       // 0x2112A442
        uint8_t  transaction_id[12]; // 96-bit unique request identifier
    };

    struct StunXorMappedAddress {
        uint16_t attr_type;   // 0x0020 (STUN_ATTR_XOR_MAPPED_ADDRESS)
        uint16_t attr_len;    // 8 bytes (reserved + family + x_port + x_ip)
        uint8_t  reserved;    // 0x00
        uint8_t  family;      // 0x01 for IPv4
        uint16_t x_port;      // port ^ (magic_cookie >> 16)
        uint32_t x_ip;        // ip ^ magic_cookie
    };

    #pragma pack(pop)



    class  StunServer{
        public:
            static constexpr uint32_t MAGIC_COOKIE = config::net::STUN_MAGIC_COOKIE;
            static constexpr uint16_t BINDING_REQUEST = config::net::STUN_BINDING_REQUEST;
            static constexpr uint16_t BINDING_RESPONSE = config::net::STUN_BINDING_RESPONSE;
            static constexpr uint16_t ATTR_XOR_MAPPED_ADDRESS = config::net::STUN_ATTR_XOR_MAPPED_ADDRESS;
            static constexpr uint16_t DEFAULT_PORT = config::net::STUN_DEFAULT_PORT;

            static constexpr size_t MIN_REQUEST_SIZE = sizeof(StunHeader);
            static constexpr size_t RESPONSE_SIZE = sizeof(StunHeader) + sizeof(StunXorMappedAddress);

            static AETHON_ALWAYS_INLINE bool is_binding_request(const uint8_t * payload, size_t len) noexcept {
                if(AETHON_UNLIKELY(len < MIN_REQUEST_SIZE)) return false;
                 const auto *hdr = reinterpret_cast<const StunHeader *>(payload);

                 // First 2 bits of STUN message type must be 0b00 (RFC 5389 Section 6)
                 // Magic cookie must strictly match 0x2112A442
                 //  Message type must be Binding Request (0x0001)

                if (AETHON_UNLIKELY((ntohs(hdr->msg_type) & 0xC000) != 0)) return false;

                if (AETHON_UNLIKELY(ntohl(hdr->magic_cookie) != MAGIC_COOKIE)) return false;

                if (AETHON_UNLIKELY(ntohs(hdr->msg_type) != BINDING_REQUEST)) return false;

                return true;
            }

            static AETHON_ALWAYS_INLINE size_t build_response(const uint8_t *req_payload,size_t req_len,uint32_t client_ip_be,uint16_t client_port_be,  uint8_t *out_buf, size_t max_out_len
            ) noexcept {
                if (AETHON_UNLIKELY(req_len < MIN_REQUEST_SIZE || max_out_len < RESPONSE_SIZE)) {
                    return 0;
                }

                const auto *req_hdr = reinterpret_cast<const StunHeader *>(req_payload);

                // write the 20 byte stun header
                auto *resp_hdr = reinterpret_cast<StunHeader *>(out_buf);
                resp_hdr->msg_type = htons(BINDING_RESPONSE); // 0x0101
                resp_hdr->msg_length = htons(static_cast<uint16_t>(sizeof(StunXorMappedAddress))); // 12 bytes
                resp_hdr->magic_cookie = htonl(MAGIC_COOKIE);

                // Echo back the exact 12-byte Transaction ID from client
                std::memcpy(resp_hdr->transaction_id, req_hdr->transaction_id, sizeof(req_hdr->transaction_id));


                auto *attr = reinterpret_cast<StunXorMappedAddress *>(out_buf + sizeof(StunHeader));
                attr->attr_type = htons(ATTR_XOR_MAPPED_ADDRESS); // 0x0020
                attr->attr_len = htons(8); // 8 bytes of payload (1 family + 1 reserved + 2 port + 4 ip)
                attr->reserved = 0x00;
                attr->family = 0x01; // IPv4


                // XOR obfuscation per RFC 5389 Section 15.2:
                // X-Port = Port ^ (MagicCookie >> 16)
                attr->x_port = client_port_be ^ htons(static_cast<uint16_t>(MAGIC_COOKIE >> 16));
                // X-IP = IPv4 ^ MagicCookie
                attr->x_ip = client_ip_be ^ htonl(MAGIC_COOKIE);
                return RESPONSE_SIZE;

            }

    };  
}