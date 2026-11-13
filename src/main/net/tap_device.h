#pragma once

#include "aethon/aethon.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

namespace aethon::net {

class TapDevice {
private:
    int tap_fd_{-1};
    std::string if_name_;

public:
    TapDevice() = default;

    ~TapDevice() {
        close();
    }

    TapDevice(const TapDevice &) = delete;
    TapDevice &operator=(const TapDevice &) = delete;

    TapDevice(TapDevice &&other) noexcept 
        : tap_fd_(other.tap_fd_), if_name_(std::move(other.if_name_)) {
        other.tap_fd_ = -1;
    }

    TapDevice &operator=(TapDevice &&other) noexcept {
        if (this != &other) {
            close();
            tap_fd_ = other.tap_fd_;
            if_name_ = std::move(other.if_name_);
            other.tap_fd_ = -1;
        }
        return *this;
    }

    // Initialize and bring UP the virtual TAP interface (e.g. "aethon0")
    bool init(const char *dev_name = "aethon0") noexcept {
        close();

        // 1. Open the Linux TUN/TAP clone device
        tap_fd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (tap_fd_ < 0) {
            return false;
        }

        // 2. Configure as Layer 2 TAP (Ethernet), without extra packet info
        struct ifreq ifr {};
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        if (dev_name && std::strlen(dev_name) > 0) {
            std::strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
        }

        if (::ioctl(tap_fd_, TUNSETIFF, reinterpret_cast<void *>(&ifr)) < 0) {
            ::close(tap_fd_);
            tap_fd_ = -1;
            return false;
        }

        if_name_ = ifr.ifr_name;

        // 3. Bring the interface UP via a temporary control socket
        int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct ifreq sock_ifr {};
            std::strncpy(sock_ifr.ifr_name, if_name_.c_str(), IFNAMSIZ - 1);
            if (::ioctl(sock, SIOCGIFFLAGS, &sock_ifr) >= 0) {
                sock_ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
                ::ioctl(sock, SIOCSIFFLAGS, &sock_ifr);
            }
            ::close(sock);
        }

        return true;
    }

    // Inject a clean raw Ethernet frame directly into the Linux kernel stack
    AETHON_ALWAYS_INLINE bool write_frame(const void *frame, size_t len) noexcept {
        if (AETHON_UNLIKELY(tap_fd_ < 0 || !frame || len == 0)) {
            return false;
        }

        ssize_t written = ::write(tap_fd_, frame, len);
        return written == static_cast<ssize_t>(len);
    }

    AETHON_ALWAYS_INLINE bool is_open() const noexcept {
        return tap_fd_ >= 0;
    }

    const std::string &name() const noexcept {
        return if_name_;
    }

    void close() noexcept {
        if (tap_fd_ >= 0) {
            ::close(tap_fd_);
            tap_fd_ = -1;
            if_name_.clear();
        }
    }
};

} // namespace aethon::net