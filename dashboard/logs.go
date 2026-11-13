package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SecurityLogEntry struct {
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Event     string `json:"event"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
	Msg       string `json:"msg"`
}

func findLogFilePath() string {
	candidates := []string{
		"logs/aethon_security.jsonl",
		"../logs/aethon_security.jsonl",
		"../../logs/aethon_security.jsonl",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Default path to create if missing
	if _, err := os.Stat("logs"); err == nil {
		return "logs/aethon_security.jsonl"
	}
	return "../logs/aethon_security.jsonl"
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	logPath := findLogFilePath()

	if r.Method == http.MethodDelete {
		_ = os.Truncate(logPath, 0)
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared", "path": logPath})
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	f, err := os.Open(logPath)
	if err != nil {
		// Log file not created yet — return empty array cleanly
		json.NewEncoder(w).Encode([]SecurityLogEntry{})
		return
	}
	defer f.Close()

	// Query parameters
	priorityFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("priority")))
	if priorityFilter == "" {
		priorityFilter = strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
	}
	moduleFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("module")))
	searchFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	sinceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("since")))

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
			if limit > 2000 {
				limit = 2000
			}
		}
	}

	// Calculate since cutoff duration
	var sinceCutoff time.Time
	if sinceFilter != "" && sinceFilter != "all" {
		var dur time.Duration
		switch sinceFilter {
		case "1m":
			dur = 1 * time.Minute
		case "5m":
			dur = 5 * time.Minute
		case "15m":
			dur = 15 * time.Minute
		case "30m":
			dur = 30 * time.Minute
		case "1h":
			dur = 1 * time.Hour
		case "24h", "1d":
			dur = 24 * time.Hour
		default:
			dur, _ = time.ParseDuration(sinceFilter)
		}
		if dur > 0 {
			sinceCutoff = time.Now().Add(-dur)
		}
	}

	// Read lines
	var allEntries []SecurityLogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry SecurityLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Priority / Level filter
		if priorityFilter != "" && priorityFilter != "ALL" {
			if strings.ToUpper(entry.Level) != priorityFilter {
				continue
			}
		}

		// Module filter
		if moduleFilter != "" && moduleFilter != "ALL" {
			if strings.ToUpper(entry.Module) != moduleFilter {
				continue
			}
		}

		// Search filter
		if searchFilter != "" {
			combined := strings.ToLower(entry.Msg + " " + entry.Event + " " + entry.SrcIP + " " + entry.DstIP)
			if !strings.Contains(combined, searchFilter) {
				continue
			}
		}

		// Time range filter
		if !sinceCutoff.IsZero() {
			if t, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
				if t.Before(sinceCutoff) {
					continue
				}
			}
		}

		allEntries = append(allEntries, entry)
	}

	// Return newest first, capped at limit
	total := len(allEntries)
	var result []SecurityLogEntry
	if total <= limit {
		result = make([]SecurityLogEntry, total)
		for i := 0; i < total; i++ {
			result[i] = allEntries[total-1-i]
		}
	} else {
		result = make([]SecurityLogEntry, limit)
		for i := 0; i < limit; i++ {
			result[i] = allEntries[total-1-i]
		}
	}

	json.NewEncoder(w).Encode(result)
}

func init() {
	// Ensure log directory exists
	path := findLogFilePath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
}
