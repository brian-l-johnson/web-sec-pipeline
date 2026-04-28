package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/jobs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockStore struct {
	jobs     map[uuid.UUID]*store.WebJob
	findings map[uuid.UUID][]store.WebFinding
	err      error
}

func newMockStore() *mockStore {
	return &mockStore{
		jobs:     make(map[uuid.UUID]*store.WebJob),
		findings: make(map[uuid.UUID][]store.WebFinding),
	}
}

func (m *mockStore) GetJob(_ context.Context, id uuid.UUID) (*store.WebJob, error) {
	if m.err != nil {
		return nil, m.err
	}
	job, ok := m.jobs[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	return job, nil
}

func (m *mockStore) ListJobs(_ context.Context, limit, offset int) ([]store.WebJob, error) {
	if m.err != nil {
		return nil, m.err
	}
	all := make([]store.WebJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		all = append(all, *j)
	}
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func (m *mockStore) CountJobs(_ context.Context) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	return len(m.jobs), nil
}

func (m *mockStore) ListFindings(_ context.Context, jobID uuid.UUID) ([]store.WebFinding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings[jobID], nil
}

type mockRetriggerer struct {
	called bool
	err    error
}

func (m *mockRetriggerer) RetriggerJob(_ context.Context, _ *store.WebJob) error {
	m.called = true
	return m.err
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeJob(status string) *store.WebJob {
	now := time.Now()
	return &store.WebJob{
		ID:           uuid.New(),
		Status:       status,
		TargetURL:    "https://example.com",
		Scope:        []string{},
		ScanProfile:  "passive",
		SubmittedAt:  now,
		CrawlStatus:  "pending",
		ZAPStatus:    "pending",
		NucleiStatus: "pending",
	}
}

type mockSubmitter struct{}

func (m *mockSubmitter) SubmitJob(_ context.Context, _ string, _ []string, _ json.RawMessage, _ string) (uuid.UUID, error) {
	return uuid.New(), nil
}

type mockReparserer struct {
	zapFindings    int
	nucleiFindings int
	err            error
}

func (m *mockReparserer) ReparseFindings(_ context.Context, _ uuid.UUID) (int, int, error) {
	return m.zapFindings, m.nucleiFindings, m.err
}

type mockLogStreamer struct{}

func (m *mockLogStreamer) StreamJobLogs(_ context.Context, _ uuid.UUID, out chan<- jobs.LogLine) {
	close(out)
}

func newTestHandler(s Storer, r JobRetriggerer) *Handler {
	return NewHandler(s, r, &mockSubmitter{}, &mockReparserer{}, &mockLogStreamer{}, "")
}

func doRequest(t *testing.T, h *Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}

func doRequestWithBody(t *testing.T, h *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHealthHandler(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/health")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want %q", resp["status"], "ok")
	}
}

func TestListJobsHandler_Empty(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp JobListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 0 {
		t.Errorf("total = %d, want 0", resp.Total)
	}
	if resp.Jobs == nil {
		resp.Jobs = []JobResponse{}
	}
	if len(resp.Jobs) != 0 {
		t.Errorf("jobs len = %d, want 0", len(resp.Jobs))
	}
}

func TestListJobsHandler_WithJobs(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp JobListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("total = %d, want 1", resp.Total)
	}
	if len(resp.Jobs) != 1 {
		t.Errorf("jobs len = %d, want 1", len(resp.Jobs))
	}
}

func TestListJobsHandler_StoreError(t *testing.T) {
	s := newMockStore()
	s.err = fmt.Errorf("db down")

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestGetJobHandler_Found(t *testing.T) {
	s := newMockStore()
	job := makeJob("running")
	s.jobs[job.ID] = job

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+job.ID.String())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp JobResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.JobID != job.ID.String() {
		t.Errorf("job_id = %q, want %q", resp.JobID, job.ID.String())
	}
	if resp.Status != "running" {
		t.Errorf("status = %q, want %q", resp.Status, "running")
	}
}

func TestGetJobHandler_NotFound(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+uuid.NewString())
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestGetJobHandler_InvalidID(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestListFindingsHandler_NoFindings(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+job.ID.String()+"/findings")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp FindingsListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 0 {
		t.Errorf("total = %d, want 0", resp.Total)
	}
}

func TestListFindingsHandler_WithFindings(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	desc := "SQL injection via login parameter"
	cwe := 89
	s.findings[job.ID] = []store.WebFinding{
		{
			ID: uuid.New(), JobID: job.ID, Tool: "nuclei",
			Severity: "high", Title: "SQLi", URL: "https://example.com/login",
			Description: &desc, CWE: &cwe,
		},
	}

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+job.ID.String()+"/findings")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp FindingsListResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 1 {
		t.Errorf("total = %d, want 1", resp.Total)
	}
	f := resp.Findings[0]
	if f.Tool != "nuclei" {
		t.Errorf("tool = %q, want %q", f.Tool, "nuclei")
	}
	if f.CWE == nil || *f.CWE != 89 {
		t.Errorf("cwe = %v, want 89", f.CWE)
	}
}

func TestListFindingsHandler_JobNotFound(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+uuid.NewString()+"/findings")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRetriggerHandler_Success(t *testing.T) {
	s := newMockStore()
	job := makeJob("failed")
	s.jobs[job.ID] = job

	rt := &mockRetriggerer{}
	h := newTestHandler(s, rt)
	rec := doRequestWithBody(t, h, http.MethodPost, "/jobs/"+job.ID.String()+"/retrigger", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if !rt.called {
		t.Error("expected RetriggerJob to be called")
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["job_id"] != job.ID.String() {
		t.Errorf("job_id = %q, want %q", resp["job_id"], job.ID.String())
	}
}

func TestRetriggerHandler_AlreadyRunning(t *testing.T) {
	s := newMockStore()
	job := makeJob("running")
	s.jobs[job.ID] = job

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequestWithBody(t, h, http.MethodPost, "/jobs/"+job.ID.String()+"/retrigger", "")
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestRetriggerHandler_NotFound(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequestWithBody(t, h, http.MethodPost, "/jobs/"+uuid.NewString()+"/retrigger", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRetriggerHandler_RetriggererError(t *testing.T) {
	s := newMockStore()
	job := makeJob("failed")
	s.jobs[job.ID] = job

	rt := &mockRetriggerer{err: fmt.Errorf("k8s unavailable")}
	h := newTestHandler(s, rt)
	rec := doRequestWithBody(t, h, http.MethodPost, "/jobs/"+job.ID.String()+"/retrigger", "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestRetriggerHandler_InvalidID(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequestWithBody(t, h, http.MethodPost, "/jobs/not-a-uuid/retrigger", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestReparseHandler_Success(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	mux := http.NewServeMux()
	h := NewHandler(s, &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{zapFindings: 3, nucleiFindings: 2}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/jobs/"+job.ID.String()+"/reparse-findings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	var resp ReparseResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.ZAPFindings != 3 {
		t.Errorf("zap_findings = %d, want 3", resp.ZAPFindings)
	}
	if resp.NucleiFindings != 2 {
		t.Errorf("nuclei_findings = %d, want 2", resp.NucleiFindings)
	}
	if resp.JobID != job.ID.String() {
		t.Errorf("job_id = %q, want %q", resp.JobID, job.ID.String())
	}
}

func TestReparseHandler_JobNotFound(t *testing.T) {
	mux := http.NewServeMux()
	h := NewHandler(newMockStore(), &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/jobs/"+uuid.NewString()+"/reparse-findings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestReparseHandler_InvalidID(t *testing.T) {
	mux := http.NewServeMux()
	h := NewHandler(newMockStore(), &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/jobs/not-a-uuid/reparse-findings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestArtifactHandler_NotFound(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	// dataDir="" so the file path won't exist → 404 artifact
	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+job.ID.String()+"/artifacts/zap")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestArtifactHandler_InvalidTool(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	h := newTestHandler(s, &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+job.ID.String()+"/artifacts/unknown")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestArtifactHandler_JobNotFound(t *testing.T) {
	h := newTestHandler(newMockStore(), &mockRetriggerer{})
	rec := doRequest(t, h, http.MethodGet, "/jobs/"+uuid.NewString()+"/artifacts/zap")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestLogsHandler_OK(t *testing.T) {
	s := newMockStore()
	job := makeJob("running")
	s.jobs[job.ID] = job

	mux := http.NewServeMux()
	h := NewHandler(s, &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/jobs/"+job.ID.String()+"/logs", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if !strings.Contains(rec.Body.String(), `"done":true`) {
		t.Errorf("body missing done event: %s", rec.Body.String())
	}
}

func TestLogsHandler_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	h := NewHandler(newMockStore(), &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/jobs/"+uuid.NewString()+"/logs", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestReparseHandler_ReparserError(t *testing.T) {
	s := newMockStore()
	job := makeJob("complete")
	s.jobs[job.ID] = job

	mux := http.NewServeMux()
	h := NewHandler(s, &mockRetriggerer{}, &mockSubmitter{}, &mockReparserer{err: fmt.Errorf("db error")}, &mockLogStreamer{}, "")
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/jobs/"+job.ID.String()+"/reparse-findings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
