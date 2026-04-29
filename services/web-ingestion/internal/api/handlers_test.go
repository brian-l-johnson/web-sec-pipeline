package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion/internal/queue"
)

// mockPublisher records published messages and optionally returns an error.
type mockPublisher struct {
	submitted []*queue.SubmittedMessage
	err       error
}

func (m *mockPublisher) PublishSubmitted(_ context.Context, msg *queue.SubmittedMessage) error {
	if m.err != nil {
		return m.err
	}
	m.submitted = append(m.submitted, msg)
	return nil
}

func newTestHandler(pub Publisher) *Handler {
	return NewHandler(pub)
}

func postScan(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ScanHandler(rec, req)
	return rec
}

// ---- ScanHandler tests ----

func TestScanHandler_Success_Minimal(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"https://example.com"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["job_id"] == "" {
		t.Fatal("missing job_id in response")
	}

	if len(pub.submitted) != 1 {
		t.Fatalf("expected 1 submitted message, got %d", len(pub.submitted))
	}
	msg := pub.submitted[0]
	if msg.TargetURL != "https://example.com" {
		t.Errorf("TargetURL = %q, want %q", msg.TargetURL, "https://example.com")
	}
	// Default profile applied.
	if msg.ScanProfile != "passive" {
		t.Errorf("ScanProfile = %q, want %q", msg.ScanProfile, "passive")
	}
	if msg.JobID != resp["job_id"] {
		t.Errorf("message JobID %q != response job_id %q", msg.JobID, resp["job_id"])
	}
	if msg.SubmittedAt == "" {
		t.Error("SubmittedAt should not be empty")
	}
}

func TestScanHandler_Success_Full(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	body := `{
		"target_url": "https://app.example.com",
		"scope": ["https://app.example.com/api/*"],
		"scan_profile": "full",
		"auth_config": {"type":"form","login_url":"https://app.example.com/login","username":"u","password":"p"}
	}`
	rec := postScan(t, h, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	if len(pub.submitted) != 1 {
		t.Fatalf("expected 1 submitted message, got %d", len(pub.submitted))
	}
	msg := pub.submitted[0]
	if msg.ScanProfile != "full" {
		t.Errorf("ScanProfile = %q, want %q", msg.ScanProfile, "full")
	}
	if len(msg.Scope) != 1 {
		t.Errorf("Scope len = %d, want 1", len(msg.Scope))
	}
	if msg.AuthConfig == nil {
		t.Error("AuthConfig should not be nil")
	}
}

func TestScanHandler_MissingTargetURL(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"scan_profile":"passive"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidTargetURL_NotHTTP(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"ftp://example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidTargetURL_Relative(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"/just/a/path"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidScanProfile(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"https://example.com","scan_profile":"aggressive"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidScopeEntry(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"https://example.com","scope":["not-a-url"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidAuthConfig(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"https://example.com","auth_config":"not json object"}`)
	// "not json object" is valid JSON (a string), but let's test truly malformed JSON embedded in the field
	if rec.Code == http.StatusInternalServerError {
		t.Errorf("should not return 500 for bad auth_config, got %d", rec.Code)
	}
}

func TestScanHandler_MalformedAuthConfigJSON(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	// Embed raw invalid JSON in auth_config field
	req := httptest.NewRequest(http.MethodPost, "/scan",
		strings.NewReader(`{"target_url":"https://example.com","auth_config":{bad}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ScanHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	pub := &mockPublisher{}
	h := newTestHandler(pub)

	rec := postScan(t, h, `not json at all`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScanHandler_PublisherError(t *testing.T) {
	pub := &mockPublisher{err: fmt.Errorf("nats down")}
	h := newTestHandler(pub)

	rec := postScan(t, h, `{"target_url":"https://example.com"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// ---- HealthHandler tests ----

func TestHealthHandler(t *testing.T) {
	h := newTestHandler(&mockPublisher{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.HealthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want %q", resp["status"], "ok")
	}
}
