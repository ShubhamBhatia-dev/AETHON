package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Paths to Aethon config files and PID

const (
	pidFilePath = "/dev/shm/aethon.pid"
)

func getServicesConfPath() string {
	candidates := []string{
		"rules/services.conf",
		"../rules/services.conf",
		"../../rules/services.conf",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/services.conf"
	}
	return "../rules/services.conf"
}

func getBlockedDomPath() string {
	candidates := []string{
		"rules/blocked_domains.txt",
		"../rules/blocked_domains.txt",
		"../../rules/blocked_domains.txt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/blocked_domains.txt"
	}
	return "../rules/blocked_domains.txt"
}

type ServiceEntry struct {
	Listen      string `json:"listen"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	BackendPort int    `json:"backend_port"`
	Proto       string `json:"proto"`
}

// signup Reload helper

func triggerAethonReload() error {
	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		return fmt.Errorf("aethon pid file not found: %w", err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid pid in %s: %w", pidFilePath, err)
	}
	return syscall.Kill(pid, syscall.SIGHUP)

}

func handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := triggerAethonReload(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "warn",
			"message": fmt.Sprintf("Config saved, but SIGHUP failed (engine running?): %v", err),
		})

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "SIGHUP sent to Aethon engine",
	})
}

// for rules/services.conf
func readServices() ([]ServiceEntry, error) {
	file, err := os.Open(getServicesConfPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []ServiceEntry{}, nil
		}
		return nil, err
	}
	defer file.Close()
	list := make([]ServiceEntry, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		backendPort, _ := strconv.Atoi(fields[3])
		proto := "https"
		if len(fields) >= 5 {
			proto = strings.ToLower(fields[4])
		}
		list = append(list, ServiceEntry{
			Listen:      fields[0],
			Cert:        fields[1],
			Key:         fields[2],
			BackendPort: backendPort,
			Proto:       proto,
		})
	}
	return list, scanner.Err()
}
func saveServicesAtomic(entries []ServiceEntry) error {
	path := getServicesConfPath()
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	tmpFile, err := os.CreateTemp(dir, "services.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)
	writer := bufio.NewWriter(tmpFile)
	for _, s := range entries {
		proto := s.Proto
		if proto == "" {
			proto = "https"
		}
		line := fmt.Sprintf("%s %s %s %d %s\n", s.Listen, s.Cert, s.Key, s.BackendPort, proto)
		if _, err := writer.WriteString(line); err != nil {
			tmpFile.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	// Atomic rename replaces the file with zero corruption window
	return os.Rename(tmpName, path)
}
func handleServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		services, err := readServices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(services)
	case http.MethodPost:
		var entry ServiceEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if entry.Listen == "" || entry.BackendPort <= 0 {
			http.Error(w, "listen address and backend_port required", http.StatusBadRequest)
			return
		}
		services, _ := readServices()
		services = append(services, entry)
		if err := saveServicesAtomic(services); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = triggerAethonReload()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func handleServiceByIndex(w http.ResponseWriter, r *http.Request) {
	// URL: /api/services/{index}
	idxStr := strings.TrimPrefix(r.URL.Path, "/api/services/")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}
	services, err := readServices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if idx < 0 || idx >= len(services) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPut:
		var updated ServiceEntry
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if updated.Listen == "" || updated.BackendPort <= 0 {
			http.Error(w, "Listen and backend_port are required", http.StatusBadRequest)
			return
		}
		services[idx] = updated
		if err := saveServicesAtomic(services); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = triggerAethonReload()
		json.NewEncoder(w).Encode(updated)

	case http.MethodDelete:
		services = append(services[:idx], services[idx+1:]...)
		if err := saveServicesAtomic(services); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = triggerAethonReload()
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// blocked_domain txt
func readBlockedDomains() ([]string, error) {
	file, err := os.Open(getBlockedDomPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer file.Close()
	domains := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}
func saveBlockedDomainsAtomic(domains []string) error {
	path := getBlockedDomPath()
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	tmpFile, err := os.CreateTemp(dir, "blocked_domains.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)
	writer := bufio.NewWriter(tmpFile)
	for _, d := range domains {
		if _, err := writer.WriteString(d + "\n"); err != nil {
			tmpFile.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
func handleBlockedDomains(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		domains, err := readBlockedDomains()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(domains)
	case http.MethodPost:
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
		if req.Domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}
		domains, _ := readBlockedDomains()
		for _, d := range domains {
			if d == req.Domain {
				json.NewEncoder(w).Encode(domains)
				return // Already present
			}
		}
		domains = append(domains, req.Domain)
		if err := saveBlockedDomainsAtomic(domains); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = triggerAethonReload()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(domains)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func handleBlockedDomainByName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// URL: /api/blocked-domains/{domain}
	dom := strings.TrimPrefix(r.URL.Path, "/api/blocked-domains/")
	dom = strings.ToLower(strings.TrimSpace(dom))
	if dom == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}
	domains, err := readBlockedDomains()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updated := make([]string, 0)
	for _, d := range domains {
		if d != dom {
			updated = append(updated, d)
		}
	}
	if err := saveBlockedDomainsAtomic(updated); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = triggerAethonReload()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
