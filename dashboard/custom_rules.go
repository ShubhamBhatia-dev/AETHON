package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var customRulesMu sync.Mutex

const disabledRulePrefix = "# [DISABLED] "

type CustomDpiRule struct {
	ID       int    `json:"id"`
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
	Src      string `json:"src"`
	SrcPort  string `json:"src_port"`
	Dir      string `json:"dir"`
	Dst      string `json:"dst"`
	DstPort  string `json:"dst_port"`
	Msg      string `json:"msg"`
	Pattern  string `json:"pattern"`
	IsPcre   bool   `json:"is_pcre"`
	Nocase   bool   `json:"nocase"`
	Sid      int    `json:"sid"`
	Rev      int    `json:"rev"`
	Enabled  bool   `json:"enabled"`
	Raw      string `json:"raw"`
}

func getCustomRulesPath() string {
	candidates := []string{
		"rules/custom_rules.rules",
		"../rules/custom_rules.rules",
		"../../rules/custom_rules.rules",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules/custom_rules.rules"
	}
	return "../rules/custom_rules.rules"
}

var (
	reOptMsg     = regexp.MustCompile(`msg\s*:\s*"([^"]*)"`)
	reOptContent = regexp.MustCompile(`content\s*:\s*"([^"]*)"`)
	reOptPcre    = regexp.MustCompile(`pcre\s*:\s*"([^"]*)"`)
	reOptSid     = regexp.MustCompile(`\bsid\s*:\s*(\d+)`)
	reOptRev     = regexp.MustCompile(`\brev\s*:\s*(\d+)`)
	reOptNocase  = regexp.MustCompile(`\bnocase\s*;`)
)

func parseCustomRuleLine(raw string, enabled bool, idx int) (CustomDpiRule, bool) {
	parenOpen := strings.IndexByte(raw, '(')
	parenClose := strings.LastIndexByte(raw, ')')
	if parenOpen < 0 || parenClose <= parenOpen {
		return CustomDpiRule{}, false
	}

	hdrFields := strings.Fields(raw[:parenOpen])
	if len(hdrFields) < 7 {
		return CustomDpiRule{}, false
	}

	action := strings.ToLower(hdrFields[0])
	if action != "drop" && action != "reject" && action != "alert" {
		return CustomDpiRule{}, false
	}

	body := raw[parenOpen+1 : parenClose]
	r := CustomDpiRule{
		ID:       idx,
		Action:   action,
		Protocol: strings.ToLower(hdrFields[1]),
		Src:      hdrFields[2],
		SrcPort:  hdrFields[3],
		Dir:      hdrFields[4],
		Dst:      hdrFields[5],
		DstPort:  hdrFields[6],
		Rev:      1,
		Enabled:  enabled,
		Raw:      raw,
	}

	if m := reOptMsg.FindStringSubmatch(body); len(m) == 2 {
		r.Msg = m[1]
	}
	if m := reOptContent.FindStringSubmatch(body); len(m) == 2 {
		r.Pattern = m[1]
		r.IsPcre = false
	} else if m := reOptPcre.FindStringSubmatch(body); len(m) == 2 {
		r.Pattern = m[1]
		r.IsPcre = true
	}
	if m := reOptSid.FindStringSubmatch(body); len(m) == 2 {
		r.Sid, _ = strconv.Atoi(m[1])
	}
	if m := reOptRev.FindStringSubmatch(body); len(m) == 2 {
		if v, err := strconv.Atoi(m[1]); err == nil && v > 0 {
			r.Rev = v
		}
	}
	r.Nocase = reOptNocase.MatchString(body)
	return r, true
}

func readCustomRulesAndHeader() ([]string, []CustomDpiRule, error) {
	path := getCustomRulesPath()
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{
				"# Aethon Custom DPI Rules (Hot-Reloadable via SIGHUP & Dashboard)",
			}, make([]CustomDpiRule, 0), nil
		}
		return nil, nil, err
	}
	defer file.Close()

	headers := make([]string, 0)
	rules := make([]CustomDpiRule, 0)
	scanner := bufio.NewScanner(file)
	inHeader := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if inHeader {
				headers = append(headers, "")
			}
			continue
		}
		if strings.HasPrefix(line, disabledRulePrefix) {
			inHeader = false
			raw := strings.TrimSpace(strings.TrimPrefix(line, disabledRulePrefix))
			if r, ok := parseCustomRuleLine(raw, false, len(rules)); ok {
				rules = append(rules, r)
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			headers = append(headers, line)
			continue
		}
		inHeader = false
		if r, ok := parseCustomRuleLine(line, true, len(rules)); ok {
			rules = append(rules, r)
		}
	}
	return headers, rules, scanner.Err()
}

func saveCustomRulesAtomic(headers []string, rules []CustomDpiRule) error {
	path := getCustomRulesPath()
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)

	tmpFile, err := os.CreateTemp(dir, "custom_rules.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	writer := bufio.NewWriter(tmpFile)
	for _, h := range headers {
		if _, err := writer.WriteString(h + "\n"); err != nil {
			tmpFile.Close()
			return err
		}
	}
	if len(headers) > 0 && headers[len(headers)-1] != "" {
		_, _ = writer.WriteString("\n")
	}
	for _, r := range rules {
		line := strings.TrimSpace(r.Raw)
		if !r.Enabled {
			line = disabledRulePrefix + line
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
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

func sanitizeQuoted(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.TrimSpace(s)
}

func nextAvailableSid(existing []CustomDpiRule) int {
	maxSid := 9000000
	for _, r := range existing {
		if r.Sid > maxSid {
			maxSid = r.Sid
		}
	}
	return maxSid + 1
}

func buildAndValidateCustomRule(req CustomDpiRule, existing []CustomDpiRule, ignoreIdx int) (CustomDpiRule, error) {
	// If user supplied a raw rule line directly, validate & parse it
	raw := strings.TrimSpace(req.Raw)
	if raw != "" {
		if strings.ContainsAny(raw, "\r\n") {
			return CustomDpiRule{}, fmt.Errorf("rule must be a single line")
		}
		parsed, ok := parseCustomRuleLine(raw, req.Enabled, 0)
		if !ok {
			return CustomDpiRule{}, fmt.Errorf("invalid rule syntax: expected '<drop|reject|alert> <proto> <src> <sport> -> <dst> <dport> (...)'")
		}
		if parsed.Protocol != "tcp" && parsed.Protocol != "http" && parsed.Protocol != "tls" &&
			parsed.Protocol != "smtp" && parsed.Protocol != "ssh" && parsed.Protocol != "ftp" && parsed.Protocol != "ip" {
			return CustomDpiRule{}, fmt.Errorf("unsupported protocol '%s' (use tcp, http, tls, or ip for TCP+UDP)", parsed.Protocol)
		}
		if strings.TrimSpace(parsed.Pattern) == "" {
			return CustomDpiRule{}, fmt.Errorf("rule must specify a non-empty content:\"...\" or pcre:\"...\" option")
		}
		if parsed.Sid <= 0 {
			return CustomDpiRule{}, fmt.Errorf("rule must include a positive sid:<number>;")
		}
		for i, r := range existing {
			if i != ignoreIdx && r.Sid == parsed.Sid {
				return CustomDpiRule{}, fmt.Errorf("SID %d already exists", parsed.Sid)
			}
		}
		return parsed, nil
	}

	// Build rule from structured form fields
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "drop"
	}
	if action != "drop" && action != "reject" && action != "alert" {
		return CustomDpiRule{}, fmt.Errorf("action must be drop, reject, or alert")
	}

	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "http" && proto != "tls" && proto != "ip" {
		return CustomDpiRule{}, fmt.Errorf("protocol must be tcp, http, tls, or ip")
	}

	msg := sanitizeQuoted(req.Msg)
	if msg == "" {
		return CustomDpiRule{}, fmt.Errorf("rule message (msg) is required")
	}
	pattern := strings.ReplaceAll(strings.ReplaceAll(req.Pattern, "\r", ""), "\n", "")
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return CustomDpiRule{}, fmt.Errorf("match pattern is required")
	}
	if req.IsPcre && !strings.HasPrefix(pattern, "/") {
		flags := ""
		if req.Nocase {
			flags = "i"
		}
		pattern = "/" + pattern + "/" + flags
	}

	sid := req.Sid
	if sid <= 0 {
		sid = nextAvailableSid(existing)
	}
	for i, r := range existing {
		if i != ignoreIdx && r.Sid == sid {
			return CustomDpiRule{}, fmt.Errorf("SID %d already exists", sid)
		}
	}

	rev := req.Rev
	if rev <= 0 {
		rev = 1
	}

	src := strings.TrimSpace(req.Src)
	if src == "" {
		src = "any"
	}
	srcPort := strings.TrimSpace(req.SrcPort)
	if srcPort == "" {
		srcPort = "any"
	}
	dst := strings.TrimSpace(req.Dst)
	if dst == "" {
		dst = "any"
	}
	dstPort := strings.TrimSpace(req.DstPort)
	if dstPort == "" {
		dstPort = "any"
	}

	var opts []string
	opts = append(opts, fmt.Sprintf(`msg:"%s"`, msg))
	if req.IsPcre {
		opts = append(opts, fmt.Sprintf(`pcre:"%s"`, strings.ReplaceAll(pattern, `"`, `\"`)))
	} else {
		opts = append(opts, fmt.Sprintf(`content:"%s"`, strings.ReplaceAll(pattern, `"`, `\"`)))
		if req.Nocase {
			opts = append(opts, "nocase")
		}
	}
	opts = append(opts, fmt.Sprintf("sid:%d", sid))
	opts = append(opts, fmt.Sprintf("rev:%d", rev))

	builtRaw := fmt.Sprintf("%s %s %s %s -> %s %s (%s;)",
		action, proto, src, srcPort, dst, dstPort, strings.Join(opts, "; "))

	parsed, ok := parseCustomRuleLine(builtRaw, req.Enabled, 0)
	if !ok {
		return CustomDpiRule{}, fmt.Errorf("failed to construct valid rule")
	}
	return parsed, nil
}

func handleCustomDpiRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	customRulesMu.Lock()
	defer customRulesMu.Unlock()

	switch r.Method {
	case http.MethodGet:
		_, rules, err := readCustomRulesAndHeader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var req CustomDpiRule
		req.Enabled = true
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		headers, rules, err := readCustomRulesAndHeader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rule, err := buildAndValidateCustomRule(req, rules, -1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rule.ID = len(rules)
		rules = append(rules, rule)
		if err := saveCustomRulesAtomic(headers, rules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reloadErr := triggerAethonReload()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rule":     rule,
			"reloaded": reloadErr == nil,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleCustomDpiRuleByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	idxStr := strings.TrimPrefix(r.URL.Path, "/api/dpi-rules/")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "invalid rule index", http.StatusBadRequest)
		return
	}

	customRulesMu.Lock()
	defer customRulesMu.Unlock()

	headers, rules, err := readCustomRulesAndHeader()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if idx < 0 || idx >= len(rules) {
		http.Error(w, "rule index out of range", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req CustomDpiRule
		req.Enabled = rules[idx].Enabled
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		rule, err := buildAndValidateCustomRule(req, rules, idx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rule.ID = idx
		rules[idx] = rule
		if err := saveCustomRulesAtomic(headers, rules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reloadErr := triggerAethonReload()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rule":     rule,
			"reloaded": reloadErr == nil,
		})

	case http.MethodDelete:
		rules = append(rules[:idx], rules[idx+1:]...)
		if err := saveCustomRulesAtomic(headers, rules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reloadErr := triggerAethonReload()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "deleted",
			"reloaded": reloadErr == nil,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
