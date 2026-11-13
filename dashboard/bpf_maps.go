// /sys/fs/bpf/aethon/<map_name>

/*
BPF_MAP_LOOKUP_ELEM = 1


BPF_MAP_UPDATE_ELEM = 2


BPF_MAP_DELETE_ELEM = 3


BPF_MAP_GET_NEXT_KEY = 4 (to iterate all keys in a map)

*/

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Linux BPF constants (x86_64)
const (
	sysBPF           = 321 // SYS_BPF syscall number
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfMapDeleteElem = 3
	bpfMapGetNextKey = 4
	pinDir           = "/sys/fs/bpf/aethon"
)

// bpfMapAttr is the 32-byte struct expected by BPF_MAP_*_ELEM commands
type bpfMapAttr struct {
	mapFd uint32
	pad0  uint32
	key   uint64 // pointer to key buffer
	value uint64 // pointer to value buffer (or next_key)
	flags uint64
}

func bpfSyscall(cmd uintptr, attr *bpfMapAttr) error {
	_, _, errno := syscall.Syscall(
		sysBPF,
		cmd,
		uintptr(unsafe.Pointer(attr)),
		uintptr(unsafe.Sizeof(*attr)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// open a pinned eBPF map

func openPinnedMap(name string) (*os.File, error) {
	path := fmt.Sprintf("%s/%s", pinDir, name)
	return os.OpenFile(path, os.O_RDWR, 0)
}

type aethonIPAddress struct {
	Addr   [16]byte
	IsIPv6 uint32
}

func parseIPv4ToAethonIP(ipStr string) (*aethonIPAddress, error) {
	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 is currently supported: %s", ipStr)
	}
	var ip aethonIPAddress
	ip.IsIPv6 = 0
	copy(ip.Addr[:4], v4)
	return &ip, nil
}
func aethonIPToString(ip *aethonIPAddress) string {
	if ip.IsIPv6 == 0 {
		return net.IP(ip.Addr[:4]).String()
	}
	return net.IP(ip.Addr[:]).String()
}

// blocked IPs (/api/blocked-ips)

type BlockedIPEntry struct {
	IP    string `json:"ip"`
	Drops uint64 `json:"drops"`
}

func handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		list := getBlockedIPs()
		json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := addBlockedIP(req.IP); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "ip": req.IP})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func handleBlockedIPByAddr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ipStr := strings.TrimPrefix(r.URL.Path, "/api/blocked-ips/")
	if err := removeBlockedIP(ipStr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "ip": ipStr})
}
func getBlockedIPs() []BlockedIPEntry {
	f, err := openPinnedMap("aethon_ip_blocklist")
	if err != nil {
		return []BlockedIPEntry{}
	}
	defer f.Close()
	fd := uint32(f.Fd())
	entries := make([]BlockedIPEntry, 0)
	var curKey aethonIPAddress
	var nextKey aethonIPAddress
	// Pass nil as key pointer for the first key
	attr := bpfMapAttr{
		mapFd: fd,
		key:   0,
		value: uint64(uintptr(unsafe.Pointer(&nextKey))),
	}
	for {
		err := bpfSyscall(bpfMapGetNextKey, &attr)
		if err != nil {
			break // No more keys
		}
		curKey = nextKey
		attr.key = uint64(uintptr(unsafe.Pointer(&curKey)))
		attr.value = uint64(uintptr(unsafe.Pointer(&nextKey)))
		// Lookup drop count value
		var dropCount uint64
		lookupAttr := bpfMapAttr{
			mapFd: fd,
			key:   uint64(uintptr(unsafe.Pointer(&curKey))),
			value: uint64(uintptr(unsafe.Pointer(&dropCount))),
		}
		if err := bpfSyscall(bpfMapLookupElem, &lookupAttr); err == nil {
			entries = append(entries, BlockedIPEntry{
				IP:    aethonIPToString(&curKey),
				Drops: dropCount,
			})
		}
	}
	return entries
}
func addBlockedIP(ipStr string) error {
	ip, err := parseIPv4ToAethonIP(ipStr)
	if err != nil {
		return err
	}
	f, err := openPinnedMap("aethon_ip_blocklist")
	if err != nil {
		return fmt.Errorf("aethon_ip_blocklist map not pinned: %w", err)
	}
	defer f.Close()
	var val uint64 = 1
	attr := bpfMapAttr{
		mapFd: uint32(f.Fd()),
		key:   uint64(uintptr(unsafe.Pointer(ip))),
		value: uint64(uintptr(unsafe.Pointer(&val))),
		flags: 0, // BPF_ANY
	}
	return bpfSyscall(bpfMapUpdateElem, &attr)
}
func removeBlockedIP(ipStr string) error {
	ip, err := parseIPv4ToAethonIP(ipStr)
	if err != nil {
		return err
	}
	f, err := openPinnedMap("aethon_ip_blocklist")
	if err != nil {
		return fmt.Errorf("aethon_ip_blocklist map not pinned: %w", err)
	}
	defer f.Close()
	attr := bpfMapAttr{
		mapFd: uint32(f.Fd()),
		key:   uint64(uintptr(unsafe.Pointer(ip))),
	}
	return bpfSyscall(bpfMapDeleteElem, &attr)
}

type RateLimiterEntry struct {
	IP        string `json:"ip"`
	Algorithm string `json:"algo"`
	Tokens    uint32 `json:"tokens"`
	Drops     uint64 `json:"drops"`
}

type RateLimiterParams struct {
	TokensPerSec uint64 `json:"tokens_per_sec"`
	WindowSec    uint64 `json:"window_sec"`
	WindowLimit  uint64 `json:"window_limit"`
}

type ServiceMapEntry struct {
	Port   uint16 `json:"port"`
	Active uint8  `json:"active"`
}

func getRateLimiterConfigPath() string {
	candidates := []string{
		"rules/rate_limiter.json",
		"../rules/rate_limiter.json",
		"../../rules/rate_limiter.json",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/rate_limiter.json"
	}
	return "../rules/rate_limiter.json"
}

func loadRateLimiterRules() []RateLimiterEntry {
	path := getRateLimiterConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		defaults := []RateLimiterEntry{
			{IP: "192.168.50.0/24", Algorithm: "Token Bucket", Tokens: 100000, Drops: 0},
			{IP: "10.0.0.0/8", Algorithm: "Sliding Window", Tokens: 50000, Drops: 0},
		}
		_ = saveRateLimiterRules(defaults)
		return defaults
	}
	rules := make([]RateLimiterEntry, 0)
	_ = json.Unmarshal(data, &rules)
	return rules
}

func saveRateLimiterRules(rules []RateLimiterEntry) error {
	path := getRateLimiterConfigPath()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func syncRateLimiterToBPF(ipStr string, algo uint16) error {
	ip, err := parseIPv4ToAethonIP(ipStr)
	if err != nil {
		return err
	}
	f, err := openPinnedMap("aethon_rate_limiter")
	if err != nil {
		return nil // map not pinned yet
	}
	defer f.Close()

	attr := bpfMapAttr{
		mapFd: uint32(f.Fd()),
		key:   uint64(uintptr(unsafe.Pointer(ip))),
		value: uint64(uintptr(unsafe.Pointer(&algo))),
		flags: 0,
	}
	return bpfSyscall(bpfMapUpdateElem, &attr)
}

func deleteRateLimiterFromBPF(ipStr string) error {
	ip, err := parseIPv4ToAethonIP(ipStr)
	if err != nil {
		return err
	}
	f, err := openPinnedMap("aethon_rate_limiter")
	if err != nil {
		return nil
	}
	defer f.Close()

	attr := bpfMapAttr{
		mapFd: uint32(f.Fd()),
		key:   uint64(uintptr(unsafe.Pointer(ip))),
	}
	return bpfSyscall(bpfMapDeleteElem, &attr)
}

func getRateLimiterEntries() []RateLimiterEntry {
	rules := loadRateLimiterRules()
	f, err := openPinnedMap("aethon_rate_limiter")
	if err != nil {
		return rules
	}
	defer f.Close()

	fd := uint32(f.Fd())
	var curKey aethonIPAddress
	var nextKey aethonIPAddress

	attr := bpfMapAttr{
		mapFd: fd,
		key:   0,
		value: uint64(uintptr(unsafe.Pointer(&nextKey))),
	}

	seen := make(map[string]bool)
	for _, r := range rules {
		seen[r.IP] = true
	}

	for {
		err := bpfSyscall(bpfMapGetNextKey, &attr)
		if err != nil {
			break
		}
		curKey = nextKey
		attr.key = uint64(uintptr(unsafe.Pointer(&curKey)))
		attr.value = uint64(uintptr(unsafe.Pointer(&nextKey)))

		var val uint16
		lookupAttr := bpfMapAttr{
			mapFd: fd,
			key:   uint64(uintptr(unsafe.Pointer(&curKey))),
			value: uint64(uintptr(unsafe.Pointer(&val))),
		}
		if err := bpfSyscall(bpfMapLookupElem, &lookupAttr); err == nil {
			ipStr := aethonIPToString(&curKey)
			if !seen[ipStr] {
				algoName := "Token Bucket"
				if val == 1 {
					algoName = "Sliding Window"
				}
				rules = append(rules, RateLimiterEntry{
					IP:        ipStr,
					Algorithm: algoName,
					Tokens:    100000,
					Drops:     0,
				})
				seen[ipStr] = true
			}
		}
	}
	return rules
}

func getRateLimiterParams() RateLimiterParams {
	params := RateLimiterParams{
		TokensPerSec: 100000,
		WindowSec:    10,
		WindowLimit:  50000,
	}

	f, err := openPinnedMap("rate_limiter_params")
	if err != nil {
		return params
	}
	defer f.Close()

	fd := uint32(f.Fd())
	var keyToken uint16 = 1
	var valToken uint64
	lookupAttr := bpfMapAttr{
		mapFd: fd,
		key:   uint64(uintptr(unsafe.Pointer(&keyToken))),
		value: uint64(uintptr(unsafe.Pointer(&valToken))),
	}
	if bpfSyscall(bpfMapLookupElem, &lookupAttr) == nil && valToken > 0 {
		params.TokensPerSec = valToken
	}

	var keyWindow uint16 = 2
	var valWindow uint64
	lookupAttr.key = uint64(uintptr(unsafe.Pointer(&keyWindow)))
	lookupAttr.value = uint64(uintptr(unsafe.Pointer(&valWindow)))
	if bpfSyscall(bpfMapLookupElem, &lookupAttr) == nil && valWindow > 0 {
		params.WindowSec = valWindow
	}

	var keyLimit uint16 = 3
	var valLimit uint64
	lookupAttr.key = uint64(uintptr(unsafe.Pointer(&keyLimit)))
	lookupAttr.value = uint64(uintptr(unsafe.Pointer(&valLimit)))
	if bpfSyscall(bpfMapLookupElem, &lookupAttr) == nil && valLimit > 0 {
		params.WindowLimit = valLimit
	}

	return params
}

func setRateLimiterParams(params RateLimiterParams) error {
	f, err := openPinnedMap("rate_limiter_params")
	if err != nil {
		return nil
	}
	defer f.Close()

	fd := uint32(f.Fd())

	var keyToken uint16 = 1
	attr := bpfMapAttr{
		mapFd: fd,
		key:   uint64(uintptr(unsafe.Pointer(&keyToken))),
		value: uint64(uintptr(unsafe.Pointer(&params.TokensPerSec))),
	}
	_ = bpfSyscall(bpfMapUpdateElem, &attr)

	var keyWindow uint16 = 2
	attr.key = uint64(uintptr(unsafe.Pointer(&keyWindow)))
	attr.value = uint64(uintptr(unsafe.Pointer(&params.WindowSec)))
	_ = bpfSyscall(bpfMapUpdateElem, &attr)

	var keyLimit uint16 = 3
	attr.key = uint64(uintptr(unsafe.Pointer(&keyLimit)))
	attr.value = uint64(uintptr(unsafe.Pointer(&params.WindowLimit)))
	_ = bpfSyscall(bpfMapUpdateElem, &attr)

	return nil
}

func getServicesMapEntries() []ServiceMapEntry {
	f, err := openPinnedMap("aethon_services_map")
	if err != nil {
		// Fallback: derive ports from services.conf
		services, _ := readServices()
		res := make([]ServiceMapEntry, 0)
		for _, s := range services {
			parts := strings.Split(s.Listen, ":")
			if len(parts) == 2 {
				var p uint16
				fmt.Sscanf(parts[1], "%d", &p)
				if p > 0 {
					res = append(res, ServiceMapEntry{Port: p, Active: 1})
				}
			}
		}
		return res
	}
	defer f.Close()

	fd := uint32(f.Fd())
	entries := make([]ServiceMapEntry, 0)
	var curKey uint16
	var nextKey uint16

	attr := bpfMapAttr{
		mapFd: fd,
		key:   0,
		value: uint64(uintptr(unsafe.Pointer(&nextKey))),
	}

	for {
		err := bpfSyscall(bpfMapGetNextKey, &attr)
		if err != nil {
			break
		}
		curKey = nextKey
		attr.key = uint64(uintptr(unsafe.Pointer(&curKey)))
		attr.value = uint64(uintptr(unsafe.Pointer(&nextKey)))

		var active uint8
		lookupAttr := bpfMapAttr{
			mapFd: fd,
			key:   uint64(uintptr(unsafe.Pointer(&curKey))),
			value: uint64(uintptr(unsafe.Pointer(&active))),
		}
		if err := bpfSyscall(bpfMapLookupElem, &lookupAttr); err == nil {
			entries = append(entries, ServiceMapEntry{
				Port:   curKey,
				Active: active,
			})
		}
	}
	return entries
}

func handleBPFRateLimiter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(getRateLimiterEntries())

	case http.MethodPost:
		var entry RateLimiterEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.IP == "" {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if entry.Algorithm == "" {
			entry.Algorithm = "Token Bucket"
		}
		if entry.Tokens == 0 {
			entry.Tokens = 100000
		}

		rules := loadRateLimiterRules()
		found := false
		for i, r := range rules {
			if r.IP == entry.IP {
				rules[i] = entry
				found = true
				break
			}
		}
		if !found {
			rules = append(rules, entry)
		}
		_ = saveRateLimiterRules(rules)

		var algoCode uint16 = 0
		if strings.EqualFold(entry.Algorithm, "Sliding Window") {
			algoCode = 1
		}
		_ = syncRateLimiterToBPF(entry.IP, algoCode)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBPFRateLimiterByIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ipStr := strings.TrimPrefix(r.URL.Path, "/api/bpf/rate-limiter/")
	if ipStr == "" {
		http.Error(w, "missing IP", http.StatusBadRequest)
		return
	}

	rules := loadRateLimiterRules()

	switch r.Method {
	case http.MethodPut:
		var updated RateLimiterEntry
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		updated.IP = ipStr
		if updated.Algorithm == "" {
			updated.Algorithm = "Token Bucket"
		}
		if updated.Tokens == 0 {
			updated.Tokens = 100000
		}

		found := false
		for i, entry := range rules {
			if entry.IP == ipStr {
				rules[i] = updated
				found = true
				break
			}
		}
		if !found {
			rules = append(rules, updated)
		}
		_ = saveRateLimiterRules(rules)

		var algoCode uint16 = 0
		if strings.EqualFold(updated.Algorithm, "Sliding Window") {
			algoCode = 1
		}
		_ = syncRateLimiterToBPF(ipStr, algoCode)

		json.NewEncoder(w).Encode(updated)

	case http.MethodDelete:
		newRules := make([]RateLimiterEntry, 0)
		for _, entry := range rules {
			if entry.IP != ipStr {
				newRules = append(newRules, entry)
			}
		}
		_ = saveRateLimiterRules(newRules)
		_ = deleteRateLimiterFromBPF(ipStr)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "ip": ipStr})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBPFRateLimiterParams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(getRateLimiterParams())

	case http.MethodPost:
		var params RateLimiterParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if params.TokensPerSec == 0 {
			params.TokensPerSec = 100000
		}
		if params.WindowSec == 0 {
			params.WindowSec = 10
		}
		if params.WindowLimit == 0 {
			params.WindowLimit = 50000
		}
		_ = setRateLimiterParams(params)
		json.NewEncoder(w).Encode(params)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBPFServicesMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getServicesMapEntries())
}

type bpfFirewallRule struct {
	SrcMAC    [6]byte
	UseSrcMAC uint8
	Pad0      uint8

	DstMAC    [6]byte
	UseDstMAC uint8
	Pad1      uint8

	SrcIP   uint32
	SrcMask uint32
	DstIP   uint32
	DstMask uint32

	SrcPort uint16
	DstPort uint16
	VlanID  uint16
	Proto   uint8
	Action  uint8 // 0 = DROP, 1 = ALLOW
	Active  uint8 // 1 = active rule
	Pad2    [3]byte
}

type FirewallRuleJSON struct {
	ID      int    `json:"id"`
	Proto   string `json:"proto"`
	SrcMAC  string `json:"src_mac"`
	DstMAC  string `json:"dst_mac"`
	SrcIP   string `json:"src_ip"`
	SrcPort string `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort string `json:"dst_port"`
	VlanID  uint16 `json:"vlan_id"`
	Action  string `json:"action"` // "ALLOW" or "DROP"
	Active  bool   `json:"active"`
}

func getFirewallRulesPath() string {
	candidates := []string{
		"rules/firewall.json",
		"../rules/firewall.json",
		"../../rules/firewall.json",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/firewall.json"
	}
	return "../rules/firewall.json"
}

func loadFirewallRules() []FirewallRuleJSON {
	path := getFirewallRulesPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return []FirewallRuleJSON{}
	}
	rules := make([]FirewallRuleJSON, 0)
	_ = json.Unmarshal(data, &rules)
	return rules
}

func saveFirewallRules(rules []FirewallRuleJSON) error {
	path := getFirewallRulesPath()
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func syncFirewallRuleToBPF(slot uint32, r *FirewallRuleJSON) error {
	f, err := openPinnedMap("aethon_firewall_map")
	if err != nil {
		return nil // map not pinned yet, fallback gracefully
	}
	defer f.Close()

	var rule bpfFirewallRule
	if r != nil && r.Active {
		rule.Active = 1

		// Protocol
		switch strings.ToUpper(r.Proto) {
		case "TCP":
			rule.Proto = 6
		case "UDP":
			rule.Proto = 17
		case "ICMP":
			rule.Proto = 1
		default:
			rule.Proto = 0
		}

		// Action
		if strings.ToUpper(r.Action) == "ALLOW" {
			rule.Action = 1
		} else {
			rule.Action = 0
		}

		// VLAN
		rule.VlanID = r.VlanID

		// MAC
		if r.SrcMAC != "" && r.SrcMAC != "*" {
			hw, err := net.ParseMAC(r.SrcMAC)
			if err == nil && len(hw) == 6 {
				copy(rule.SrcMAC[:], hw)
				rule.UseSrcMAC = 1
			}
		}
		if r.DstMAC != "" && r.DstMAC != "*" {
			hw, err := net.ParseMAC(r.DstMAC)
			if err == nil && len(hw) == 6 {
				copy(rule.DstMAC[:], hw)
				rule.UseDstMAC = 1
			}
		}

		// Ports
		if r.SrcPort != "" && r.SrcPort != "*" {
			var sp uint16
			fmt.Sscanf(r.SrcPort, "%d", &sp)
			rule.SrcPort = sp
		}
		if r.DstPort != "" && r.DstPort != "*" {
			var dp uint16
			fmt.Sscanf(r.DstPort, "%d", &dp)
			rule.DstPort = dp
		}

		// IPs & Subnet Masks
		parseCIDRorIP := func(s string) (uint32, uint32) {
			s = strings.TrimSpace(s)
			if s == "" || s == "*" {
				return 0, 0
			}
			if strings.Contains(s, "/") {
				_, ipNet, err := net.ParseCIDR(s)
				if err == nil && ipNet.IP.To4() != nil {
					ip := binary.LittleEndian.Uint32(ipNet.IP.To4())
					mask := binary.LittleEndian.Uint32(ipNet.Mask)
					return ip, mask
				}
			}
			ip := net.ParseIP(s)
			if ip != nil && ip.To4() != nil {
				return binary.LittleEndian.Uint32(ip.To4()), 0xFFFFFFFF
			}
			return 0, 0
		}

		rule.SrcIP, rule.SrcMask = parseCIDRorIP(r.SrcIP)
		rule.DstIP, rule.DstMask = parseCIDRorIP(r.DstIP)
	}

	attr := bpfMapAttr{
		mapFd: uint32(f.Fd()),
		key:   uint64(uintptr(unsafe.Pointer(&slot))),
		value: uint64(uintptr(unsafe.Pointer(&rule))),
	}
	return bpfSyscall(bpfMapUpdateElem, &attr)
}

func handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		rules := loadFirewallRules()
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var req FirewallRuleJSON
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		rules := loadFirewallRules()
		req.ID = len(rules)
		req.Active = true
		if req.Proto == "" {
			req.Proto = "ALL"
		}
		if req.Action == "" {
			req.Action = "DROP"
		}
		if req.SrcIP == "" {
			req.SrcIP = "*"
		}
		if req.DstIP == "" {
			req.DstIP = "*"
		}
		if req.SrcPort == "" {
			req.SrcPort = "*"
		}
		if req.DstPort == "" {
			req.DstPort = "*"
		}
		if req.SrcMAC == "" {
			req.SrcMAC = "*"
		}
		if req.DstMAC == "" {
			req.DstMAC = "*"
		}

		rules = append(rules, req)
		_ = saveFirewallRules(rules)
		_ = syncFirewallRuleToBPF(uint32(req.ID), &req)
		_ = triggerAethonReload()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(req)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleFirewallRuleByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/firewall/rules/")
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		http.Error(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	rules := loadFirewallRules()
	if id < 0 || id >= len(rules) {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPut:
		var updated FirewallRuleJSON
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		updated.ID = id
		if updated.Proto == "" {
			updated.Proto = "TCP"
		}
		if updated.Action == "" {
			updated.Action = "ALLOW"
		}
		if updated.SrcIP == "" {
			updated.SrcIP = "*"
		}
		if updated.DstIP == "" {
			updated.DstIP = "*"
		}
		if updated.SrcPort == "" {
			updated.SrcPort = "*"
		}
		if updated.DstPort == "" {
			updated.DstPort = "*"
		}
		if updated.SrcMAC == "" {
			updated.SrcMAC = "*"
		}
		if updated.DstMAC == "" {
			updated.DstMAC = "*"
		}

		rules[id] = updated
		_ = saveFirewallRules(rules)
		_ = syncFirewallRuleToBPF(uint32(id), &updated)
		_ = triggerAethonReload()
		json.NewEncoder(w).Encode(updated)

	case http.MethodDelete:
		// Remove from list
		rules = append(rules[:id], rules[id+1:]...)
		// Re-index remaining rules and sync all to BPF
		for i := range rules {
			rules[i].ID = i
			_ = syncFirewallRuleToBPF(uint32(i), &rules[i])
		}
		// Clear the last slot
		_ = syncFirewallRuleToBPF(uint32(len(rules)), nil)

		_ = saveFirewallRules(rules)
		_ = triggerAethonReload()
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────────────────────
// Engine Operation Mode (match_only map)
// 0 = Bypass (XDP_PASS directly to Linux OS network stack)
// 1 = Match-Only (audit/monitor: rules & limits evaluate, NO drop)
// 2 = Full Protection (active drops and deep inspection; DEFAULT)
// ─────────────────────────────────────────────────────────────

type EngineModeConfig struct {
	Mode int `json:"mode"`
}

func getEngineModePath() string {
	candidates := []string{
		"rules/engine_mode.json",
		"../rules/engine_mode.json",
		"../../rules/engine_mode.json",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/engine_mode.json"
	}
	return "../rules/engine_mode.json"
}

func getEngineMode() int {
	// 1. Try reading from pinned BPF map
	f, err := openPinnedMap("match_only")
	if err == nil {
		defer f.Close()
		fd := uint32(f.Fd())
		var key uint32 = 0
		var val uint32 = 2
		attr := bpfMapAttr{
			mapFd: fd,
			key:   uint64(uintptr(unsafe.Pointer(&key))),
			value: uint64(uintptr(unsafe.Pointer(&val))),
		}
		_, _, errno := syscall.Syscall(sysBPF, uintptr(bpfMapLookupElem), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		if errno == 0 {
			return int(val)
		}
	}

	// 2. Fallback to saved config file
	data, err := os.ReadFile(getEngineModePath())
	if err == nil {
		var cfg EngineModeConfig
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.Mode >= 0 && cfg.Mode <= 2 {
			return cfg.Mode
		}
	}

	// 3. Default to 2 (Full Protection)
	return 2
}

func setEngineMode(mode int) error {
	if mode < 0 || mode > 2 {
		return fmt.Errorf("invalid mode: must be 0 (Bypass), 1 (Match-Only), or 2 (Full Protection)")
	}

	// 1. Persist to file
	p := getEngineModePath()
	_ = os.MkdirAll(filepath.Dir(p), 0755)
	data, _ := json.MarshalIndent(EngineModeConfig{Mode: mode}, "", "  ")
	_ = os.WriteFile(p, data, 0644)

	// 2. Sync to pinned BPF map if present
	f, err := openPinnedMap("match_only")
	if err == nil {
		defer f.Close()
		fd := uint32(f.Fd())
		var key uint32 = 0
		var val uint32 = uint32(mode)
		attr := bpfMapAttr{
			mapFd: fd,
			key:   uint64(uintptr(unsafe.Pointer(&key))),
			value: uint64(uintptr(unsafe.Pointer(&val))),
			flags: 0,
		}
		_, _, errno := syscall.Syscall(sysBPF, uintptr(bpfMapUpdateElem), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		if errno != 0 {
			return fmt.Errorf("bpf update match_only: %v", errno)
		}
	}

	// 3. Notify engine
	_ = triggerAethonReload()
	return nil
}

func handleEngineMode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		mode := getEngineMode()
		modeNames := map[int]string{
			0: "Bypass",
			1: "Match Only",
			2: "Full Protection",
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": mode,
			"name": modeNames[mode],
		})

	case http.MethodPost:
		var req struct {
			Mode int `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := setEngineMode(req.Mode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		modeNames := map[int]string{
			0: "Bypass",
			1: "Match Only",
			2: "Full Protection",
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":   req.Mode,
			"name":   modeNames[req.Mode],
			"status": "updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
