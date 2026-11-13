package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed web/*
var embeddedFiles embed.FS

func main() {
	mux := http.NewServeMux()

	//  1. Embedded Static Web Files
	webContent, err := fs.Sub(embeddedFiles, "web")
	if err != nil {
		log.Fatalf("Failed to locate web files: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webContent)))

	//  2. Telemetry & Stats API
	mux.HandleFunc("/api/stats", corsMiddleware(handleStats))
	mux.HandleFunc("/api/live", corsMiddleware(handleLive))
	mux.HandleFunc("/api/logs", corsMiddleware(handleLogs))

	//  Services Configuration (rules/services.conf)
	mux.HandleFunc("/api/services", corsMiddleware(handleServices))
	mux.HandleFunc("/api/services/", corsMiddleware(handleServiceByIndex))

	// SNI Blocklist (rules/blocked_domains.txt)
	mux.HandleFunc("/api/blocked-domains", corsMiddleware(handleBlockedDomains))
	mux.HandleFunc("/api/blocked-domains/", corsMiddleware(handleBlockedDomainByName))

	// Custom DPI Rules (rules/custom_rules.rules - hot-reloaded via SIGHUP)
	mux.HandleFunc("/api/dpi-rules", corsMiddleware(handleCustomDpiRules))
	mux.HandleFunc("/api/dpi-rules/", corsMiddleware(handleCustomDpiRuleByID))

	//  eBPF Pinned Maps
	mux.HandleFunc("/api/blocked-ips", corsMiddleware(handleBlockedIPs))
	mux.HandleFunc("/api/blocked-ips/", corsMiddleware(handleBlockedIPByAddr))
	mux.HandleFunc("/api/bpf/rate-limiter/params", corsMiddleware(handleBPFRateLimiterParams))
	mux.HandleFunc("/api/bpf/rate-limiter", corsMiddleware(handleBPFRateLimiter))
	mux.HandleFunc("/api/bpf/rate-limiter/", corsMiddleware(handleBPFRateLimiterByIP))
	mux.HandleFunc("/api/bpf/services-map", corsMiddleware(handleBPFServicesMap))

	mux.HandleFunc("/api/reload", corsMiddleware(handleReload))

	// Firewall ACL Rules
	mux.HandleFunc("/api/firewall/rules", corsMiddleware(handleFirewallRules))
	mux.HandleFunc("/api/firewall/rules/", corsMiddleware(handleFirewallRuleByID))

	// Engine Operation Mode (match_only map: 0 = Bypass, 1 = Match-Only, 2 = Full Protection)
	mux.HandleFunc("/api/engine/mode", corsMiddleware(handleEngineMode))

	addr := ":2384"
	log.Printf("  AETHON GATEWAY DASHBOARD ONLINE")
	log.Printf("  Access Console at: http://localhost%s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// corsMiddleware adds headers so the frontend can interact without CORS issues
func corsMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// handleStats returns the live stats from shared memory (/dev/shm/aethon_stats.shm)
func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	stats := GetLiveStats()
	if stats == nil {
		// When Aethon C++ is offline, return basic placeholder JSON so dashboard still renders
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rx_packets_per_sec": 0,
			"rx_bytes_per_sec":   0,
			"total_packets":      0,
			"total_bytes":        0,
			"active_sessions":    0,
			"engine_mode":        getEngineMode(),
			"uptime":             "offline (engine not running)",
			"events":             map[string]uint64{},
			"xdp_stats": map[int]XdpStat{
				0: {Packets: 0, Bytes: 0},
				1: {Packets: 0, Bytes: 0},
				2: {Packets: 0, Bytes: 0},
				3: {Packets: 0, Bytes: 0},
				4: {Packets: 0, Bytes: 0},
			},
		})
		return
	}
	json.NewEncoder(w).Encode(stats)
}

func formatBytesRate(b uint64) string {
	if b == 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	val := float64(b)
	i := 0
	for val >= 1024 && i < len(units)-1 {
		val /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", val, units[i])
}

// handleLive provides a Server-Sent Events (SSE) stream for real-time live events
func handleLive(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sendSSE := func(sev, msg string) {
		ts := time.Now().Format("15:04:05")
		data, _ := json.Marshal(map[string]string{
			"ts":  ts,
			"sev": sev,
			"msg": msg,
		})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	sendSSE("OK", "Connected to Aethon SSE Stream")

	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	var lastEvents map[string]uint64
	var lastXdpDrop uint64
	var lastThroughputReport time.Time

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			stats := GetLiveStats()
			if stats == nil {
				continue
			}

			// Check event deltas
			if lastEvents != nil {
				if d := stats.Events["rst_dpi_match"] - lastEvents["rst_dpi_match"]; d > 0 {
					sendSSE("ATTACK", fmt.Sprintf("ATTACK DETECTED: Deep Packet Inspection (DPI) exploit signature matched — TCP RST injected (%d times)", d))
				}
				if d := stats.Events["rst_sni_blocked"] - lastEvents["rst_sni_blocked"]; d > 0 {
					sendSSE("ATTACK", fmt.Sprintf("ATTACK DETECTED: Blacklisted TLS SNI domain intercepted — TCP RST injected (%d times)", d))
				}
				if d := stats.Events["ja3_rate_limited"] - lastEvents["ja3_rate_limited"]; d > 0 {
					sendSSE("ATTACK", fmt.Sprintf("ATTACK DETECTED: JA3 TLS fingerprint abuse / botnet rate-limited — SYN dropped (%d times)", d))
				}
				if d := stats.Events["rst_overlap_evasion"] - lastEvents["rst_overlap_evasion"]; d > 0 {
					sendSSE("ATTACK", fmt.Sprintf("ATTACK DETECTED: TCP segment overlap evasion attempt (IDS evasion attack) — connection terminated (%d times)", d))
				}
				if d := stats.Events["rst_bad_client_hello"] - lastEvents["rst_bad_client_hello"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("Malformed TLS ClientHello discarded (%d times)", d))
				}
				if d := stats.Events["rst_tls_error"] - lastEvents["rst_tls_error"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("TLS decryption/handshake error (%d resets sent)", d))
				}
				if d := stats.Events["rst_backend_failed"] - lastEvents["rst_backend_failed"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("Backend connection failure: RST dispatched (%d times)", d))
				}
				if d := stats.Events["syn_cookie_sent"] - lastEvents["syn_cookie_sent"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("SYN queue under pressure: %d stateless SYN cookies dispatched", d))
				}
				if d := stats.Events["syn_cookie_accepted"] - lastEvents["syn_cookie_accepted"]; d > 0 {
					sendSSE("OK", fmt.Sprintf("SYN cookie verified: %d connection validated", d))
				}
				if d := stats.Events["syn_dropped_memory_pressure"] - lastEvents["syn_dropped_memory_pressure"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("High memory pressure: %d SYN packets dropped", d))
				}
				if d := stats.Events["session_expired_idle"] - lastEvents["session_expired_idle"]; d > 0 {
					sendSSE("INFO", fmt.Sprintf("Session idle timeout: %d sessions expired and cleaned up", d))
				}
				if d := stats.Events["tcp_bad_checksum"] - lastEvents["tcp_bad_checksum"]; d > 0 {
					sendSSE("WARN", fmt.Sprintf("Invalid TCP checksum (%d packets discarded)", d))
				}
				if d := stats.Events["icmp_pmtu_update"] - lastEvents["icmp_pmtu_update"]; d > 0 {
					sendSSE("INFO", fmt.Sprintf("ICMP Packet-Too-Big handled: Path MTU cache updated (%d times)", d))
				}
			}

			// Check XDP_DROP delta
			currentXdpDrop := stats.XdpStats[1].Packets
			if lastEvents != nil && currentXdpDrop > lastXdpDrop {
				d := currentXdpDrop - lastXdpDrop
				sendSSE("ATTACK", fmt.Sprintf("ATTACK DETECTED: eBPF XDP Hardware Firewall — %d packets blocked at wire speed", d))
			}
			lastXdpDrop = currentXdpDrop

			// Snapshot events
			lastEvents = make(map[string]uint64, len(stats.Events))
			for k, v := range stats.Events {
				lastEvents[k] = v
			}

			// Throughput report only when active or once every 30s
			now := time.Now()
			if stats.RxPacketsPerSec > 0 {
				sendSSE("INFO", fmt.Sprintf("Throughput: %d pps (%s/s) | %d active sessions",
					stats.RxPacketsPerSec, formatBytesRate(stats.RxBytesPerSec), stats.ActiveSessions))
				lastThroughputReport = now
			} else if now.Sub(lastThroughputReport) > 30*time.Second {
				if stats.TotalPackets > 0 {
					sendSSE("OK", fmt.Sprintf("Engine idle — %d total packets processed | %d active sessions",
						stats.TotalPackets, stats.ActiveSessions))
				}
				lastThroughputReport = now
			}
		}
	}
}
