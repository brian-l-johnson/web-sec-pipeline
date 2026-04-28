package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	cronlib "github.com/robfig/cron/v3"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// TargetStorer covers target and schedule persistence.
type TargetStorer interface {
	CreateTarget(ctx context.Context, t store.ScanTarget) error
	GetTarget(ctx context.Context, id uuid.UUID) (*store.ScanTarget, error)
	ListTargets(ctx context.Context) ([]store.ScanTarget, error)
	UpdateTarget(ctx context.Context, t store.ScanTarget) error
	DeleteTarget(ctx context.Context, id uuid.UUID) error

	CreateSchedule(ctx context.Context, sc store.ScanSchedule) error
	GetSchedule(ctx context.Context, id uuid.UUID) (*store.ScanSchedule, error)
	ListSchedules(ctx context.Context, targetID uuid.UUID) ([]store.ScanSchedule, error)
	UpdateSchedule(ctx context.Context, sc store.ScanSchedule) error
	DeleteSchedule(ctx context.Context, id uuid.UUID) error
	SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool, nextRunAt *time.Time) error
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

type TargetResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	TargetURL   string             `json:"target_url"`
	Scope       []string           `json:"scope"`
	ScanProfile string             `json:"scan_profile"`
	Schedules   []ScheduleResponse `json:"schedules,omitempty"`
	CreatedAt   string             `json:"created_at"`
	UpdatedAt   string             `json:"updated_at"`
}

type ScheduleResponse struct {
	ID          string `json:"id"`
	TargetID    string `json:"target_id"`
	CronExpr    string `json:"cron_expr"`
	WindowStart string `json:"window_start,omitempty"`
	WindowEnd   string `json:"window_end,omitempty"`
	Enabled     bool   `json:"enabled"`
	LastRunAt   string `json:"last_run_at,omitempty"`
	NextRunAt   string `json:"next_run_at,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func targetToResponse(t *store.ScanTarget) TargetResponse {
	scope := t.Scope
	if scope == nil {
		scope = []string{}
	}
	return TargetResponse{
		ID:          t.ID.String(),
		Name:        t.Name,
		TargetURL:   t.TargetURL,
		Scope:       scope,
		ScanProfile: t.ScanProfile,
		CreatedAt:   t.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   t.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func scheduleToResponse(sc *store.ScanSchedule) ScheduleResponse {
	r := ScheduleResponse{
		ID:        sc.ID.String(),
		TargetID:  sc.TargetID.String(),
		CronExpr:  sc.CronExpr,
		Enabled:   sc.Enabled,
		CreatedAt: sc.CreatedAt.UTC().Format(time.RFC3339),
	}
	if sc.WindowStart != nil {
		r.WindowStart = *sc.WindowStart
	}
	if sc.WindowEnd != nil {
		r.WindowEnd = *sc.WindowEnd
	}
	if sc.LastRunAt != nil {
		r.LastRunAt = sc.LastRunAt.UTC().Format(time.RFC3339)
	}
	if sc.NextRunAt != nil {
		r.NextRunAt = sc.NextRunAt.UTC().Format(time.RFC3339)
	}
	return r
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

func (h *Handler) registerTargetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /targets",                  h.ListTargetsHandler)
	mux.HandleFunc("POST /targets",                 h.CreateTargetHandler)
	mux.HandleFunc("GET /targets/{id}",             h.GetTargetHandler)
	mux.HandleFunc("PUT /targets/{id}",             h.UpdateTargetHandler)
	mux.HandleFunc("DELETE /targets/{id}",          h.DeleteTargetHandler)
	mux.HandleFunc("POST /targets/{id}/scan",       h.ScanTargetHandler)
	mux.HandleFunc("GET /targets/{id}/schedules",   h.ListSchedulesHandler)
	mux.HandleFunc("POST /targets/{id}/schedules",  h.CreateScheduleHandler)
	mux.HandleFunc("PUT /schedules/{id}",           h.UpdateScheduleHandler)
	mux.HandleFunc("DELETE /schedules/{id}",        h.DeleteScheduleHandler)
	mux.HandleFunc("PATCH /schedules/{id}/enabled", h.SetScheduleEnabledHandler)
}

// ---------------------------------------------------------------------------
// Target handlers
// ---------------------------------------------------------------------------

func (h *Handler) ListTargetsHandler(w http.ResponseWriter, r *http.Request) {
	targets, err := h.targetStore.ListTargets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing targets: "+err.Error())
		return
	}
	resp := make([]TargetResponse, len(targets))
	for i := range targets {
		resp[i] = targetToResponse(&targets[i])
		schedules, _ := h.targetStore.ListSchedules(r.Context(), targets[i].ID)
		for j := range schedules {
			resp[i].Schedules = append(resp[i].Schedules, scheduleToResponse(&schedules[j]))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) CreateTargetHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		TargetURL   string          `json:"target_url"`
		Scope       []string        `json:"scope"`
		ScanProfile string          `json:"scan_profile"`
		AuthConfig  json.RawMessage `json:"auth_config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := validateTargetFields(req.Name, req.TargetURL, req.ScanProfile); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ScanProfile == "" {
		req.ScanProfile = "passive"
	}
	t := store.ScanTarget{
		ID:          uuid.New(),
		Name:        strings.TrimSpace(req.Name),
		TargetURL:   req.TargetURL,
		Scope:       req.Scope,
		AuthConfig:  req.AuthConfig,
		ScanProfile: req.ScanProfile,
	}
	if t.Scope == nil {
		t.Scope = []string{}
	}
	if err := h.targetStore.CreateTarget(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, "creating target: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, targetToResponse(&t))
}

func (h *Handler) GetTargetHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	t, err := h.targetStore.GetTarget(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting target: "+err.Error())
		return
	}
	resp := targetToResponse(t)
	schedules, _ := h.targetStore.ListSchedules(r.Context(), id)
	for i := range schedules {
		resp.Schedules = append(resp.Schedules, scheduleToResponse(&schedules[i]))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) UpdateTargetHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	var req struct {
		Name        string          `json:"name"`
		TargetURL   string          `json:"target_url"`
		Scope       []string        `json:"scope"`
		ScanProfile string          `json:"scan_profile"`
		AuthConfig  json.RawMessage `json:"auth_config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := validateTargetFields(req.Name, req.TargetURL, req.ScanProfile); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ScanProfile == "" {
		req.ScanProfile = "passive"
	}
	t := store.ScanTarget{
		ID:          id,
		Name:        strings.TrimSpace(req.Name),
		TargetURL:   req.TargetURL,
		Scope:       req.Scope,
		AuthConfig:  req.AuthConfig,
		ScanProfile: req.ScanProfile,
	}
	if t.Scope == nil {
		t.Scope = []string{}
	}
	if err := h.targetStore.UpdateTarget(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, "updating target: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, targetToResponse(&t))
}

func (h *Handler) DeleteTargetHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	if err := h.targetStore.DeleteTarget(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "deleting target: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ScanTargetHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	t, err := h.targetStore.GetTarget(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting target: "+err.Error())
		return
	}
	jobID, err := h.submitter.SubmitJob(r.Context(), t.TargetURL, t.Scope, t.AuthConfig, t.ScanProfile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "submitting scan: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID.String(), "status": "accepted"})
}

// ---------------------------------------------------------------------------
// Schedule handlers
// ---------------------------------------------------------------------------

func (h *Handler) ListSchedulesHandler(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	schedules, err := h.targetStore.ListSchedules(r.Context(), targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing schedules: "+err.Error())
		return
	}
	resp := make([]ScheduleResponse, len(schedules))
	for i := range schedules {
		resp[i] = scheduleToResponse(&schedules[i])
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) CreateScheduleHandler(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target ID")
		return
	}
	var req struct {
		CronExpr    string `json:"cron_expr"`
		WindowStart string `json:"window_start"`
		WindowEnd   string `json:"window_end"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	nextRun, err := nextCronRun(req.CronExpr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
		return
	}
	if err := validateWindow(req.WindowStart, req.WindowEnd); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	sc := store.ScanSchedule{
		ID:          uuid.New(),
		TargetID:    targetID,
		CronExpr:    req.CronExpr,
		Enabled:     enabled,
		WindowStart: nilIfEmpty(req.WindowStart),
		WindowEnd:   nilIfEmpty(req.WindowEnd),
	}
	if enabled {
		sc.NextRunAt = &nextRun
	}
	if err := h.targetStore.CreateSchedule(r.Context(), sc); err != nil {
		writeError(w, http.StatusInternalServerError, "creating schedule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, scheduleToResponse(&sc))
}

func (h *Handler) UpdateScheduleHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}
	existing, err := h.targetStore.GetSchedule(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting schedule: "+err.Error())
		return
	}
	var req struct {
		CronExpr    string `json:"cron_expr"`
		WindowStart string `json:"window_start"`
		WindowEnd   string `json:"window_end"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	nextRun, err := nextCronRun(req.CronExpr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
		return
	}
	if err := validateWindow(req.WindowStart, req.WindowEnd); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	existing.CronExpr    = req.CronExpr
	existing.WindowStart = nilIfEmpty(req.WindowStart)
	existing.WindowEnd   = nilIfEmpty(req.WindowEnd)
	existing.NextRunAt   = &nextRun
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if err := h.targetStore.UpdateSchedule(r.Context(), *existing); err != nil {
		writeError(w, http.StatusInternalServerError, "updating schedule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scheduleToResponse(existing))
}

func (h *Handler) DeleteScheduleHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}
	if err := h.targetStore.DeleteSchedule(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "deleting schedule: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SetScheduleEnabledHandler(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	sc, err := h.targetStore.GetSchedule(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "getting schedule: "+err.Error())
		return
	}
	var nextRun *time.Time
	if req.Enabled {
		if t, err := nextCronRun(sc.CronExpr); err == nil {
			nextRun = &t
		}
	}
	if err := h.targetStore.SetScheduleEnabled(r.Context(), id, req.Enabled, nextRun); err != nil {
		writeError(w, http.StatusInternalServerError, "updating schedule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id.String(), "enabled": req.Enabled})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func nextCronRun(expr string) (time.Time, error) {
	p := cronlib.NewParser(cronlib.Minute | cronlib.Hour | cronlib.Dom | cronlib.Month | cronlib.Dow)
	sched, err := p.Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(time.Now()), nil
}

func validateTargetFields(name, targetURL, profile string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("name is required")
	}
	p, err := url.ParseRequestURI(targetURL)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return fmt.Errorf("target_url must be a valid http/https URL")
	}
	switch profile {
	case "", "passive", "active", "full":
	default:
		return fmt.Errorf("scan_profile must be one of: passive, active, full")
	}
	return nil
}

func validateWindow(start, end string) error {
	if start == "" && end == "" {
		return nil
	}
	if (start == "") != (end == "") {
		return fmt.Errorf("window_start and window_end must both be provided or both omitted")
	}
	for label, t := range map[string]string{"window_start": start, "window_end": end} {
		if !isValidHHMM(t) {
			return fmt.Errorf("%s must be in HH:MM format (UTC)", label)
		}
	}
	return nil
}

func isValidHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	for i, c := range s {
		if i == 2 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
