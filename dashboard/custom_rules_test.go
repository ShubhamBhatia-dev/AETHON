package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCustomDpiRulesCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	rulesFile := filepath.Join(rulesDir, "custom_rules.rules")
	if err := os.WriteFile(rulesFile, []byte("# Header comment\n"), 0644); err != nil {
		t.Fatal(err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	// 1. GET empty
	req := httptest.NewRequest(http.MethodGet, "/api/dpi-rules", nil)
	rec := httptest.NewRecorder()
	handleCustomDpiRules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var list []CustomDpiRule
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(list))
	}

	// 2. POST structured rule
	body := `{"action":"drop","protocol":"http","msg":"Block Admin","pattern":"/.env","nocase":true,"sid":9000001,"enabled":true}`
	req = httptest.NewRequest(http.MethodPost, "/api/dpi-rules", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	handleCustomDpiRules(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Reject duplicate SID
	req = httptest.NewRequest(http.MethodPost, "/api/dpi-rules", bytes.NewBufferString(body))
	rec = httptest.NewRecorder()
	handleCustomDpiRules(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate SID expected 400, got %d", rec.Code)
	}

	// 4. PUT disable rule
	putBody := `{"action":"alert","protocol":"tcp","msg":"Audit Admin","pattern":"/.env","nocase":true,"sid":9000001,"enabled":false}`
	req = httptest.NewRequest(http.MethodPut, "/api/dpi-rules/0", bytes.NewBufferString(putBody))
	rec = httptest.NewRecorder()
	handleCustomDpiRuleByID(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify file preserves header and marks disabled rule
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("# Header comment")) || !bytes.Contains(data, []byte(disabledRulePrefix+"alert tcp")) {
		t.Fatalf("unexpected file contents:\n%s", string(data))
	}

	// 5. DELETE rule
	req = httptest.NewRequest(http.MethodDelete, "/api/dpi-rules/0", nil)
	rec = httptest.NewRecorder()
	handleCustomDpiRuleByID(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
