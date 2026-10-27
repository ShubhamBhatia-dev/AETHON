#pragma once

#include "aethon/aethon.h"
#include "aethon/fast_vector.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

namespace aethon {

struct ReassemblyBuffer {
    alignas(implementation::hardware_destructive_interference_size) uint8_t  data[65536];
    alignas(implementation::hardware_destructive_interference_size) uint64_t bitmap[1024];
};

class ReassemblyBufferPool {
private:
    static constexpr size_t POOL_SIZE = 256;

    std::unique_ptr<ReassemblyBuffer[]> storage_{new ReassemblyBuffer[POOL_SIZE]};
    aethon::SmallVector<ReassemblyBuffer*, POOL_SIZE> free_list_;

public:
    ReassemblyBufferPool() {
        for (size_t i = 0; i < POOL_SIZE; ++i) {
            free_list_.push_back(&storage_[i]);
        }
    }

    ReassemblyBuffer *acquire() noexcept {
        if (AETHON_UNLIKELY(free_list_.empty())) {
            return nullptr;
        }

        ReassemblyBuffer *buf = free_list_.back();
        free_list_.pop_back();

        std::memset(buf->bitmap, 0, sizeof(buf->bitmap));
        return buf;
    }

    void release(ReassemblyBuffer *buf) noexcept {
        if (AETHON_LIKELY(buf != nullptr)) {
            free_list_.push_back(buf);
        }
    }
};

} // namespace aethon