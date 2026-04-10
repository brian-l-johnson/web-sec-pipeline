package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// Storer is the subset of store.Store used by the HTTP handlers.
type Storer interface {
	GetJob(ctx context.Context, id uuid.UUID) (*store.WebJob, error)
	ListJobs(ctx context.Context, limit, offset int) ([]store.WebJob, error)
	CountJobs(ctx context.Context) (int, error)
	ListFindings(ctx context.Context, jobID uuid.UUID) ([]store.WebFinding, error)
}

// JobRetriggerer is the subset of pipeline.Orchestrator used by the HTTP handlers.
type JobRetriggerer interface {
	RetriggerJob(ctx context.Context, job *store.WebJob) error
}

// Handler holds shared dependencies for the HTTP handlers.
type Handler struct {
	store       Storer
	retriggerer JobRetriggerer
}

// NewHandler creates a Handler.
func NewHandler(s Storer, r JobRetriggerer) *Handler {
	return &Handler{store: s, retriggerer: r}
}

// RegisterRoutes wires all routes into mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.HealthHandler)
	mux.HandleFunc("GET /jobs", h.ListJobsHandler)
	mux.HandleFunc("GET /jobs/{id}", h.GetJobHandler)
	mux.HandleFunc("GET /jobs/{id}/findings", h.ListFindingsHandler)
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

// JobResponse is the JSON representation of a web_jobs row.
type JobResponse struct {
	JobID        string `json:"job_id"`
	Status       string `json:"status"`
	TargetURL    string `json:"target_url"`
	ScanProfile  string `json:"scan_profile"`
	SubmittedAt  string `json:"submitted_at"`
	StartedAt    string `json:"started_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
	CrawlStatus  string `json:"crawl_status"`
	ZAPStatus    string `json:"zap_status"`
	NucleiStatus string `json:"nuclei_status"`
	HARPath      string `json:"har_path,omitempty"`
	Error        string `json:"error,omitempty"`
}

// FindingResponse is the JSON representation of a web_findings row.
type FindingResponse struct {
	ID          string `json:"id"`
	JobID       string `json:"job_id"`
	Tool        string `json:"tool"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	CWE         *int   `json:"cwe,omitempty"`
	TemplateID  string `json:"template_id,omitempty"`
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
		ID:       f.ID.String(),
		JobID:    f.JobID.String(),
		Tool:     f.Tool,
		Severity: f.Severity,
		Title:    f.Title,
		URL:      f.URL,
		CWE:      f.CWE,
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// HealthHandler handles GET /health.
//
// @Summary      Health check
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
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
