#pragma once

#include "aethon/aethon.h"
#include "config/constants.h"
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <unistd.h>

namespace aethon {

class WorkerMemoryBudget {
private:
    size_t current_bytes_{0};
    size_t max_bytes_{config::memory::DEFAULT_WORKER_BUDGET};

public:
    static size_t calculate_default_budget(size_t num_workers = 4) noexcept {
        // how many total physical memory pages exist on this machine
        long pages = sysconf(_SC_PHYS_PAGES);
        long page_size = sysconf(_SC_PAGE_SIZE);
        if (pages <= 0 || page_size <= 0) return config::memory::DEFAULT_WORKER_BUDGET;
        size_t total_ram = static_cast<size_t>(pages) * static_cast<size_t>(page_size);
        // ~40% of total host RAM divided across workers
        size_t budget_total = static_cast<size_t>(total_ram * config::memory::HOST_RAM_PERCENTAGE);
        return std::max<size_t>(config::memory::MIN_BUDGET_BYTES, budget_total / std::max<size_t>(1, num_workers));
    }

    WorkerMemoryBudget() noexcept : max_bytes_(calculate_default_budget()) {}
    explicit WorkerMemoryBudget(size_t max_bytes) noexcept : max_bytes_(max_bytes) {}

    AETHON_ALWAYS_INLINE void allocate(size_t bytes) noexcept {
        current_bytes_ += bytes;
    }

    AETHON_ALWAYS_INLINE void deallocate(size_t bytes) noexcept {
        current_bytes_ = (current_bytes_ >= bytes) ? (current_bytes_ - bytes) : 0;
    }

    AETHON_ALWAYS_INLINE size_t current_bytes() const noexcept {
        return current_bytes_;
    }

    AETHON_ALWAYS_INLINE size_t max_bytes() const noexcept {
        return max_bytes_;
    }

    AETHON_ALWAYS_INLINE void set_max_bytes(size_t bytes) noexcept {
        max_bytes_ = bytes;
    }

    AETHON_ALWAYS_INLINE bool is_over_budget() const noexcept {
        return current_bytes_ >= max_bytes_;
    }

    // Critical state for aggressive eviction of oldest idle sessions
    AETHON_ALWAYS_INLINE bool is_critical() const noexcept {
        return current_bytes_ >= (max_bytes_ * config::memory::CRITICAL_WATERMARK_PCT) / 100;
    }

    AETHON_ALWAYS_INLINE size_t available_bytes() const noexcept {
        return (max_bytes_ > current_bytes_) ? (max_bytes_ - current_bytes_) : 0;
    }
};

} // namespace aethon
