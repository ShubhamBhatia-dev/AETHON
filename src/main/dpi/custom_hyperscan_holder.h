#pragma once

#include "hyper_scan_engine.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace aethon {
namespace scan {

/**
 * @brief Immutable snapshot of a compiled custom Hyperscan DPI database generation.
 * Kept alive in CustomHyperscanHolder so open hs_stream_t handles never dangle.
 */
struct CustomScannerGeneration {
    uint64_t id{0};
    rules::RuleDatabase rule_db;
    HyperscanEngine engine;
    bool active{false};
};

/**
 * @brief Thread-safe double-buffered holder for hot-reloadable custom DPI rules.
 *
 * Mirrors ServiceRegistryHolder: SIGHUP compiles a new draft database off the packet
 * hot path and swaps an atomic pointer with release/acquire semantics. Previous
 * generations remain alive until process exit so worker streams never hit UAF.
 */
class CustomHyperscanHolder {
private:
    std::atomic<const CustomScannerGeneration *> current_{nullptr};
    std::vector<std::unique_ptr<CustomScannerGeneration>> generations_;
    std::mutex reload_mutex_;
    AlertCallback alert_cb_{};
    uint64_t next_id_{1};

public:
    CustomHyperscanHolder() = default;

    void set_alert_callback(AlertCallback cb) noexcept {
        std::lock_guard<std::mutex> lock(reload_mutex_);
        alert_cb_ = std::move(cb);
    }

    /**
     * @brief Loads and compiles custom rules from disk into a fresh generation.
     * On Hyperscan compile error, retains the previous working generation.
     */
    bool reload_from_file(const std::string &filepath, CompileStats *out_stats = nullptr) {
        std::lock_guard<std::mutex> lock(reload_mutex_);

        auto draft = std::make_unique<CustomScannerGeneration>();
        draft->id = next_id_++;

        auto load_st = draft->rule_db.load_with_policy(filepath, rules::RuleDatabase::LoadMode::CUSTOM);
        CompileStats cs;

        if (!draft->rule_db.empty()) {
            draft->engine.set_alert_callback([this](const AttackAlert &alert) {
                if (alert_cb_) {
                    alert_cb_(alert);
                }
            });
            if (!draft->engine.compile_rules(draft->rule_db, cs)) {
                std::cerr << "[CustomDPI] Compile FAILED for " << filepath
                          << " (" << load_st.loaded << " rules); keeping previous active rule set.\n";
                if (out_stats) *out_stats = cs;
                return false;
            }
            draft->active = true;
        } else {
            draft->active = false;
        }

        if (out_stats) *out_stats = cs;

        const CustomScannerGeneration *ptr = draft.get();
        generations_.push_back(std::move(draft));
        current_.store(ptr, std::memory_order_release);
        return true;
    }

    AETHON_ALWAYS_INLINE const CustomScannerGeneration *get() const noexcept {
        return current_.load(std::memory_order_acquire);
    }
};

} // namespace scan
} // namespace aethon
