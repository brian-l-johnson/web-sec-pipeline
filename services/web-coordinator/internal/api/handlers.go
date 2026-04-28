package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/jobs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// Storer is the subset of store.Store used by the HTTP handlers.
type Storer interface {
	GetJob(ctx context.Context, id uuid.UUID) (*store.WebJob, error)
	ListJobs(ctx context.Context, limit, offset int) ([]store.WebJob, error)
	CountJobs(ctx context.Context) (int, error)
	ListFindings(ctx context.Context, jobID uuid.UUID) ([]store.WebFinding, error)
	TriageFinding(ctx context.Context, findingID, jobID uuid.UUID, status string) error
	ListFindingsSummaries(ctx context.Context, jobIDs []uuid.UUID) (map[uuid.UUID]store.FindingsSummary, error)
	Ping(ctx context.Context) error
}

// JobRetriggerer is the subset of pipeline.Orchestrator used by the HTTP handlers.
type JobRetriggerer interface {
	RetriggerJob(ctx context.Context, job *store.WebJob) error
}

// JobSubmitter can create a new scan job directly.
type JobSubmitter interface {
	SubmitJob(ctx context.Context, targetURL string, scope []string, authConfig json.RawMessage, scanProfile string) (uuid.UUID, error)
}

// FindingsReparserer can re-parse on-disk scan reports for a job without
// re-running the underlying scanners.
type FindingsReparserer interface {
	ReparseFindings(ctx context.Context, jobID uuid.UUID) (zapFindings, nucleiFindings int, err error)
}

// JobLogStreamer streams scan pod log lines for a job over a channel.
type JobLogStreamer interface {
	StreamJobLogs(ctx context.Context, jobID uuid.UUID, out chan<- jobs.LogLine)
}

// Handler holds shared dependencies for the HTTP handlers.
type Handler struct {
	store        Storer
	retriggerer  JobRetriggerer
	submitter    JobSubmitter
	reparserer   FindingsReparserer
	logStreamer   JobLogStreamer
	dataDir      string
	healthChecks []func(ctx context.Context) error
}

// AddHealthCheck registers a function that is called by HealthHandler. If any
// check returns an error the endpoint responds 503.
func (h *Handler) AddHealthCheck(fn func(ctx context.Context) error) {
	h.healthChecks = append(h.healthChecks, fn)
}

// NewHandler creates a Handler.
func NewHandler(s Storer, r JobRetriggerer, sub JobSubmitter, rep FindingsReparserer, ls JobLogStreamer, dataDir string) *Handler {
	return &Handler{store: s, retriggerer: r, submitter: sub, reparserer: rep, logStreamer: ls, dataDir: dataDir}
}

// RegisterRoutes wires all routes into mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.HealthHandler)
	mux.HandleFunc("GET /jobs", h.ListJobsHandler)
	mux.HandleFunc("POST /jobs", h.SubmitJobHandler)
	mux.HandleFunc("GET /jobs/{id}", h.GetJobHandler)
	mux.HandleFunc("GET /jobs/{id}/findings", h.ListFindingsHandler)
	mux.HandleFunc("PATCH /jobs/{id}/findings/{findingId}", h.TriageHandler)
	mux.HandleFunc("GET /jobs/{id}/artifacts/{tool}", h.ArtifactHandler)
	mux.HandleFunc("GET /jobs/{id}/logs", h.LogsHandler)
	mux.HandleFunc("POST /jobs/{id}/reparse-findings", h.ReparseHandler)
	mux.HandleFunc("POST /jobs/{id}/retrigger", h.RetriggerHandler)
}

// writeJSON writes a JSON-encoded value with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// FindingsSummaryResponse holds per-severity finding counts, excluding false positives.
type FindingsSummaryResponse struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// JobResponse is the JSON representation of a web_jobs row.
type JobResponse struct {
	JobID           string                   `json:"job_id"`
	Status          string                   `json:"status"`
	TargetURL       string                   `json:"target_url"`
	ScanProfile     string                   `json:"scan_profile"`
	SubmittedAt     string                   `json:"submitted_at"`
	StartedAt       string                   `json:"started_at,omitempty"`
	CompletedAt     string                   `json:"completed_at,omitempty"`
	CrawlStatus     string                   `json:"crawl_status"`
	ZAPStatus       string                   `json:"zap_status"`
	NucleiStatus    string                   `json:"nuclei_status"`
	HARPath         string                   `json:"har_path,omitempty"`
	Error           string                   `json:"error,omitempty"`
	FindingsSummary *FindingsSummaryResponse `json:"findings_summary,omitempty"`
}

// FindingResponse is the JSON representation of a web_findings row.
type FindingResponse struct {
	ID           string `json:"id"`
	JobID        string `json:"job_id"`
	Tool         string `json:"tool"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	Description  string `json:"description,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	CWE          *int   `json:"cwe,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TriageStatus string `json:"triage_status"`
}

// JobListResponse wraps a paginated list of jobs.
type JobListResponse struct {
	Total int           `json:"total"`
	Jobs  []JobResponse `json:"jobs"`
}

// FindingsListResponse wraps a list of findings.
type FindingsListResponse struct {
	Total    int               `json:"total"`
	Findings []FindingResponse `json:"findings"`
}

// ReparseResponse is returned by POST /jobs/{id}/reparse-findings.
type ReparseResponse struct {
	JobID          string `json:"job_id"`
	ZAPFindings    int    `json:"zap_findings"`
	NucleiFindings int    `json:"nuclei_findings"`
}

func jobToResponse(j *store.WebJob) JobResponse {
	r := JobResponse{
		JobID:        j.ID.String(),
		Status:       j.Status,
		TargetURL:    j.TargetURL,
		ScanProfile:  j.ScanProfile,
		SubmittedAt:  j.SubmittedAt.UTC().Format(time.RFC3339),
		StartedAt:    formatTime(j.StartedAt),
		CompletedAt:  formatTime(j.CompletedAt),
		CrawlStatus:  j.CrawlStatus,
		ZAPStatus:    j.ZAPStatus,
		NucleiStatus: j.NucleiStatus,
	}
	if j.HARPath != nil {
		r.HARPath = *j.HARPath
	}
	if j.Error != nil {
		r.Error = *j.Error
	}
	return r
}

func findingToResponse(f *store.WebFinding) FindingResponse {
	r := FindingResponse{
		ID:           f.ID.String(),
		JobID:        f.JobID.String(),
		Tool:         f.Tool,
		Severity:     f.Severity,
		Title:        f.Title,
		URL:          f.URL,
		CWE:          f.CWE,
		TriageStatus: f.TriageStatus,
	}
	if f.Description != nil {
		r.Description = *f.Description
	}
	if f.Evidence != nil {
		r.Evidence = *f.Evidence
	}
	if f.TemplateID != nil {
		r.TemplateID = *f.TemplateID
	}
	return r
}

// submitJobRequest is the request body for POST /jobs.
type submitJobRequest struct {
	TargetURL   string          `json:"target_url"`
	ScanProfile string          `json:"scan_profile"`
	Scope       []string        `json:"scope"`
	AuthConfig  json.RawMessage `json:"auth_config,omitempty" swaggertype:"object"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// SubmitJobHandler handles POST /jobs — submit a new scan job from the web UI.
//
// @Summary      Submit a new scan job
// @Tags         jobs
// @Accept       json
// @Produce      json
// @Param        body  body  api.submitJobRequest  true  "Scan request"
// @Success      202  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /jobs [post]
func (h *Handler) SubmitJobHandler(w http.ResponseWriter, r *http.Request) {
	var req submitJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate target URL.
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	if req.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "target_url is required")
		return
	}
	parsed, err := url.ParseRequestURI(req.TargetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		writeError(w, http.StatusBadRequest, "target_url must be a valid http/https URL")
		return
	}
	// Strip fragment — it's client-side routing only, scanners should never see it.
	parsed.Fragment = ""
	req.TargetURL = parsed.String()

	// Validate scan_profile.
	if req.ScanProfile == "" {
		req.ScanProfile = "passive"
	}
	switch req.ScanProfile {
	case "passive", "active", "full":
	default:
		writeError(w, http.StatusBadRequest, "scan_profile must be one of: passive, active, full")
		return
	}

	// Validate scope entries.
	for _, s := range req.Scope {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := url.ParseRequestURI(strings.TrimSuffix(s, "*"))
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
			writeError(w, http.StatusBadRequest, "scope entries must be valid http/https URLs or wildcard patterns")
			return
		}
	}

	// Validate auth_config JSON (if provided).
	if len(req.AuthConfig) > 0 && !json.Valid(req.AuthConfig) {
		writeError(w, http.StatusBadRequest, "auth_config must be valid JSON")
		return
	}

	jobID, err := h.submitter.SubmitJob(r.Context(), req.TargetURL, req.Scope, req.AuthConfig, req.ScanProfile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "submit job: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String(), "status": "accepted"})
}

// HealthHandler handles GET /health.
//
// @Summary      Health check
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      503  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	for _, check := range h.healthChecks {
		if err := check(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy", "error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ListJobsHandler handles GET /jobs.
//
// @Summary      List scan jobs
// @Tags         jobs
// @Produce      json
// @Param        limit   query  int  false  "Max results (default 20)"
// @Param        offset  query  int  false  "Pagination offset"
// @Success      200  {object}  api.JobListResponse
// @Router       /jobs [get]
func (h *Handler) ListJobsHandler(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	total, err := h.store.CountJobs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "counting jobs: "+err.Error())
		return
	}

	jobList, err := h.store.ListJobs(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing jobs: "+err.Error())
		return
	}

	resp := JobListResponse{
		Total: total,
		Jobs:  make([]JobResponse, len(jobList)),
	}
	for i := range jobList {
		resp.Jobs[i] = jobToResponse(&jobList[i])
	}

	// Attach findings summaries in one query.
	ids := make([]uuid.UUID, len(jobList))
	for i, j := range jobList {
		ids[i] = j.ID
	}
	if summaries, err := h.store.ListFindingsSummaries(r.Context(), ids); err == nil {
		for i := range resp.Jobs {
			id, _ := uuid.Parse(resp.Jobs[i].JobID)
			if s, ok := summaries[id]; ok {
				resp.Jobs[i].FindingsSummary = &FindingsSummaryResponse{
					Critical: s.Critical,
					High:     s.High,
					Medium:   s.Medium,
					Low:      s.Low,
					Info:     s.Info,
					Total:    s.Critical + s.High + s.Medium + s.Low + s.Info,
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetJobHandler handles GET /jobs/{id}.
//
// @Summary      Get a scan job by ID
// @Tags         jobs
// @Produce      json
// @Param        id  path  string  true  "Job UUID"
// @Success      200  {object}  api.JobResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /jobs/{id} [get]
func (h *Handler) GetJobHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	job, err := h.store.GetJob(r.Context(), jobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, jobToResponse(job))
}

// ListFindingsHandler handles GET /jobs/{id}/findings.
//
// @Summary      List findings for a scan job
// @Tags         jobs
// @Produce      json
// @Param        id  path  string  true  "Job UUID"
// @Success      200  {object}  api.FindingsListResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /jobs/{id}/findings [get]
func (h *Handler) ListFindingsHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	// Verify the job exists first.
	if _, err := h.store.GetJob(r.Context(), jobID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	findings, err := h.store.ListFindings(r.Context(), jobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing findings: "+err.Error())
		return
	}

	resp := FindingsListResponse{
		Total:    len(findings),
		Findings: make([]FindingResponse, len(findings)),
	}
	for i := range findings {
		resp.Findings[i] = findingToResponse(&findings[i])
	}
	writeJSON(w, http.StatusOK, resp)
}

// TriageHandler handles PATCH /jobs/{id}/findings/{findingId}.
// Updates the triage_status of a single finding.
//
// @Summary      Triage a finding
// @Tags         jobs
// @Accept       json
// @Produce      json
// @Param        id         path  string  true  "Job UUID"
// @Param        findingId  path  string  true  "Finding UUID"
// @Param        body       body  object  true  "triage_status: new|confirmed|false_positive"
// @Success      200  {object}  api.FindingResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /jobs/{id}/findings/{findingId} [patch]
func (h *Handler) TriageHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	findingID, err := uuid.Parse(r.PathValue("findingId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding ID")
		return
	}

	var req struct {
		TriageStatus string `json:"triage_status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	switch req.TriageStatus {
	case "new", "confirmed", "false_positive":
	default:
		writeError(w, http.StatusBadRequest, "triage_status must be one of: new, confirmed, false_positive")
		return
	}

	if err := h.store.TriageFinding(r.Context(), findingID, jobID, req.TriageStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "triaging finding: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":            findingID.String(),
		"triage_status": req.TriageStatus,
	})
}

// ArtifactHandler handles GET /jobs/{id}/artifacts/{tool}.
// Serves the raw scanner output file as a download.
//
// @Summary      Download raw scanner output
// @Tags         jobs
// @Param        id    path  string  true  "Job UUID"
// @Param        tool  path  string  true  "Tool (zap, nuclei, crawl)"
// @Success      200
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /jobs/{id}/artifacts/{tool} [get]
func (h *Handler) ArtifactHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	type artifactSpec struct {
		path        string
		filename    string
		contentType string
	}
	specs := map[string]artifactSpec{
		"zap":    {fmt.Sprintf("%s/output/%s/zap/report.json", h.dataDir, jobID), fmt.Sprintf("zap-report-%s.json", jobID.String()[:8]), "application/json"},
		"nuclei": {fmt.Sprintf("%s/output/%s/nuclei/nuclei.jsonl", h.dataDir, jobID), fmt.Sprintf("nuclei-%s.jsonl", jobID.String()[:8]), "application/json"},
		"crawl":  {fmt.Sprintf("%s/output/%s/crawl/capture.har", h.dataDir, jobID), fmt.Sprintf("crawl-%s.har", jobID.String()[:8]), "application/json"},
	}

	spec, ok := specs[r.PathValue("tool")]
	if !ok {
		writeError(w, http.StatusBadRequest, "tool must be one of: zap, nuclei, crawl")
		return
	}

	if _, err := h.store.GetJob(r.Context(), jobID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	f, err := os.Open(spec.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "artifact not available — scan may not have completed yet")
			return
		}
		writeError(w, http.StatusInternalServerError, "opening artifact: "+err.Error())
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", spec.contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, spec.filename))
	io.Copy(w, f) //nolint:errcheck
}

// LogsHandler handles GET /jobs/{id}/logs as a Server-Sent Events stream.
// Each event is a JSON object: {"tool":"zap","text":"..."}.
// A final {"done":true} event is sent when all tool logs have been exhausted.
//
// @Summary      Stream scan pod logs
// @Description  Server-Sent Events stream of log lines from the crawl, ZAP, and Nuclei pods. Follows pods until they exit; waits up to 90 minutes for tools that haven't started yet.
// @Tags         jobs
// @Produce      text/event-stream
// @Param        id  path  string  true  "Job UUID"
// @Success      200
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /jobs/{id}/logs [get]
func (h *Handler) LogsHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	if _, err := h.store.GetJob(r.Context(), jobID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	lineCh := make(chan jobs.LogLine, 64)
	go h.logStreamer.StreamJobLogs(r.Context(), jobID, lineCh)

	enc := json.NewEncoder(w)
	for line := range lineCh {
		fmt.Fprint(w, "data: ")
		enc.Encode(line) // appends \n
		fmt.Fprint(w, "\n")
		flusher.Flush()
	}

	fmt.Fprint(w, "data: {\"done\":true}\n\n")
	flusher.Flush()
}

// ReparseHandler handles POST /jobs/{id}/reparse-findings.
//
// @Summary      Re-parse on-disk scan reports
// @Description  Deletes existing findings for the job and re-reads the ZAP and Nuclei report files from disk. Useful when findings failed to store due to a parsing bug. Does not re-run the scanners.
// @Tags         jobs
// @Produce      json
// @Param        id  path  string  true  "Job UUID"
// @Success      200  {object}  api.ReparseResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /jobs/{id}/reparse-findings [post]
func (h *Handler) ReparseHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	if _, err := h.store.GetJob(r.Context(), jobID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	zapN, nucleiN, err := h.reparserer.ReparseFindings(r.Context(), jobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reparse findings: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ReparseResponse{
		JobID:          jobID.String(),
		ZAPFindings:    zapN,
		NucleiFindings: nucleiN,
	})
}

// RetriggerHandler handles POST /jobs/{id}/retrigger.
//
// @Summary      Retrigger a scan job
// @Description  Resets a failed or complete job and re-runs the full scan pipeline.
// @Tags         jobs
// @Produce      json
// @Param        id  path  string  true  "Job UUID"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /jobs/{id}/retrigger [post]
func (h *Handler) RetriggerHandler(w http.ResponseWriter, r *http.Request) {
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	job, err := h.store.GetJob(r.Context(), jobID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting job: "+err.Error())
		return
	}

	if job.Status == "running" {
		writeError(w, http.StatusConflict, "job is already running")
		return
	}

	if err := h.retriggerer.RetriggerJob(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, "retriggering job: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "retriggered", "job_id": jobID.String()})
}
