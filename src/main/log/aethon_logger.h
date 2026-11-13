#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// FluxIO kernel-bypass storage backend
#include <fluxio.h>

namespace aethon::log {

struct SecurityLogEntry {
  uint64_t timestamp_ns;
  char level[16];      // "INFO", "WARN", "ALERT", "CRITICAL"
  char module[24];     // "DPI", "FIREWALL", "TLS", "TCP", "RATE_LIMIT"
  char event[32];      // "DPI_SIGNATURE_MATCH", "SNI_BLOCKED", etc.
  char src_ip[46];
  uint16_t src_port;
  char dst_ip[46];
  uint16_t dst_port;
  char proto[8];
  char action[16];     // "BLOCK", "RESET", "DROP", "ALLOW"
  char msg[256];
};

class AsyncFluxLogger {
public:
  static AsyncFluxLogger& instance() {
    static AsyncFluxLogger s_instance;
    return s_instance;
  }

  bool start(const char* log_file_path = "logs/aethon_security.jsonl") {
    if (running_.load(std::memory_order_relaxed)) {
      return true;
    }

    log_path_ = log_file_path;
    try {
      std::filesystem::path p(log_path_);
      if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path());
      }
    } catch (...) {}

    // Security audit log is a plain append-only JSONL file (the dashboard tails it).
    // The FluxIO io_uring path wrote block-aligned chunks into a preallocated file,
    // which left the file as unreadable padding (no newline-delimited JSON ever
    // reached the dashboard, so attacks never showed). Use the reliable POSIX append
    // instead, and start each run with a fresh file so stale padding can't jam the
    // dashboard's line scanner.
    io_uring_active_ = false;
    try { std::filesystem::remove(log_path_); } catch (...) {}
    file_offset_ = 0;

    running_.store(true, std::memory_order_release);
    worker_thread_ = std::thread(&AsyncFluxLogger::flush_loop, this);
    return true;
  }

  void stop() {
    if (!running_.load(std::memory_order_relaxed)) return;
    running_.store(false, std::memory_order_release);
    cv_.notify_all();
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
    // Flush remaining
    drain_queue();
  }

  void push_log(const char* level, const char* module, const char* event,
                const char* src_ip, uint16_t src_port,
                const char* dst_ip, uint16_t dst_port,
                const char* proto, const char* action,
                const char* msg) {
    if (!running_.load(std::memory_order_relaxed)) return;

    SecurityLogEntry entry{};
    entry.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    
    std::strncpy(entry.level, level ? level : "INFO", sizeof(entry.level) - 1);
    std::strncpy(entry.module, module ? module : "CORE", sizeof(entry.module) - 1);
    std::strncpy(entry.event, event ? event : "EVENT", sizeof(entry.event) - 1);
    std::strncpy(entry.src_ip, src_ip ? src_ip : "0.0.0.0", sizeof(entry.src_ip) - 1);
    entry.src_port = src_port;
    std::strncpy(entry.dst_ip, dst_ip ? dst_ip : "0.0.0.0", sizeof(entry.dst_ip) - 1);
    entry.dst_port = dst_port;
    std::strncpy(entry.proto, proto ? proto : "TCP", sizeof(entry.proto) - 1);
    std::strncpy(entry.action, action ? action : "PASS", sizeof(entry.action) - 1);
    std::strncpy(entry.msg, msg ? msg : "", sizeof(entry.msg) - 1);

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (queue_.size() < MAX_QUEUE_SIZE) {
        queue_.push_back(entry);
      }
    }
    cv_.notify_one();
  }

private:
  AsyncFluxLogger() = default;
  ~AsyncFluxLogger() { stop(); }

  static constexpr size_t MAX_QUEUE_SIZE = 16384;
  static constexpr size_t FLUX_BLOCK_SIZE = 4096;

  std::string log_path_{"logs/aethon_security.jsonl"};
  std::atomic<bool> running_{false};
  bool io_uring_active_{false};
  uint64_t file_offset_{0};

  flux::DefaultStorageEngine flux_engine_;
  std::thread worker_thread_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::vector<SecurityLogEntry> queue_;

  void flush_loop() {
    std::vector<SecurityLogEntry> local_batch;
    local_batch.reserve(512);

    while (running_.load(std::memory_order_acquire)) {
      {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
          return !queue_.empty() || !running_.load(std::memory_order_relaxed);
        });

        if (queue_.empty() && !running_.load(std::memory_order_relaxed)) {
          break;
        }

        local_batch.swap(queue_);
      }

      if (!local_batch.empty()) {
        write_batch(local_batch);
        local_batch.clear();
      }
    }
  }

  void drain_queue() {
    std::vector<SecurityLogEntry> remaining;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      remaining.swap(queue_);
    }
    if (!remaining.empty()) {
      write_batch(remaining);
    }
  }

  void write_batch(const std::vector<SecurityLogEntry>& batch) {
    if (batch.empty()) return;

    std::string formatted;
    formatted.reserve(batch.size() * 256);

    char time_str[64];
    for (const auto& item : batch) {
      // Format ISO 8601 timestamp
      std::time_t sec = item.timestamp_ns / 1000000000ULL;
      uint32_t usec = (item.timestamp_ns % 1000000000ULL) / 1000;
      std::tm tm_buf;
      gmtime_r(&sec, &tm_buf);
      std::snprintf(time_str, sizeof(time_str), "%04d-%02d-%02dT%02d:%02d:%02d.%06uZ",
                    tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                    tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, usec);

      // Construct JSON line
      formatted.append("{\"ts\":\"");
      formatted.append(time_str);
      formatted.append("\",\"level\":\"");
      formatted.append(item.level);
      formatted.append("\",\"module\":\"");
      formatted.append(item.module);
      formatted.append("\",\"event\":\"");
      formatted.append(item.event);
      formatted.append("\",\"src_ip\":\"");
      formatted.append(item.src_ip);
      formatted.append("\",\"src_port\":");
      formatted.append(std::to_string(item.src_port));
      formatted.append(",\"dst_ip\":\"");
      formatted.append(item.dst_ip);
      formatted.append("\",\"dst_port\":");
      formatted.append(std::to_string(item.dst_port));
      formatted.append(",\"proto\":\"");
      formatted.append(item.proto);
      formatted.append("\",\"action\":\"");
      formatted.append(item.action);
      formatted.append("\",\"msg\":\"");
      // Escape basic quotes in msg if any
      for (const char* p = item.msg; *p; ++p) {
        if (*p == '"' || *p == '\\') formatted.push_back('\\');
        formatted.push_back(*p);
      }
      formatted.append("\"}\n");
    }

    if (formatted.empty()) return;

    // Use FluxIO asynchronous I/O if available
    if (io_uring_active_) {
      // Align write to block size or write directly
      size_t len = formatted.size();
      size_t offset = 0;

      while (offset < len) {
        size_t chunk = std::min(len - offset, FLUX_BLOCK_SIZE);
        flux::IORequest req{};
        req.op_type = flux::Type::Write;
        req.file_slot = 0;
        req.length = chunk;
        req.file_offset = file_offset_;
        req.user_data = file_offset_;
        req.data_src = formatted.data() + offset;

        flux_engine_.push_request(std::move(req));
        flux_engine_.process_submissions();

        file_offset_ += chunk;
        offset += chunk;
      }

      // Poll completions to reap cqes
      flux_engine_.poll_completion();
      flux::IoCompletion comp{};
      while (flux_engine_.try_pop_completion(comp)) {}
    } else {
      // Posix/std fallback
      FILE* fp = std::fopen(log_path_.c_str(), "a");
      if (fp) {
        std::fwrite(formatted.data(), 1, formatted.size(), fp);
        std::fflush(fp);
        std::fclose(fp);
        file_offset_ += formatted.size();
      }
    }
  }
};

// Global helper functions
inline void init_logger(const char* path = "logs/aethon_security.jsonl") {
  AsyncFluxLogger::instance().start(path);
}

inline void shutdown_logger() {
  AsyncFluxLogger::instance().stop();
}

inline void log_event(const char* level, const char* module, const char* event,
                      const char* src_ip, uint16_t src_port,
                      const char* dst_ip, uint16_t dst_port,
                      const char* proto, const char* action,
                      const char* msg) {
  AsyncFluxLogger::instance().push_log(level, module, event, src_ip, src_port,
                                       dst_ip, dst_port, proto, action, msg);
}

} // namespace aethon::log
