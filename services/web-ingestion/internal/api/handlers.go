package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-ingestion/internal/queue"
	"github.com/google/uuid"
)

// Publisher is the subset of queue.Publisher used by the handlers.
type Publisher interface {
	PublishSubmitted(ctx context.Context, msg *queue.SubmittedMessage) error
	PublishFailed(ctx context.Context, msg *queue.FailedMessage) error
}

// Handler holds shared dependencies for the HTTP handlers.
type Handler struct {
	publisher Publisher
}

// NewHandler creates a Handler with the provided publisher.
func NewHandler(publisher Publisher) *Handler {
	return &Handler{publisher: publisher}
}

// writeJSON writes a JSON-encoded value with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// writeError writes a JSON error body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// validScanProfiles is the set of accepted scan_profile values.
var validScanProfiles = map[string]bool{
	"passive": true,
	"active":  true,
	"full":    true,
}

// validateURL returns true if s is a valid http or https URL with a non-empty host.
func validateURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// ScanRequest is the JSON body expected by POST /scan.
type ScanRequest struct {
	TargetURL   string          `json:"target_url"`
	Scope       []string        `json:"scope"`
	AuthConfig  json.RawMessage `json:"auth_config,omitempty" swaggertype:"object"`
	ScanProfile string          `json:"scan_profile"`
}

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

// ScanHandler handles POST /scan.
//
// @Summary      Submit a web scan
// @Description  Validates the request and publishes it to NATS for the coordinator to pick up.
// @Tags         ingestion
// @Accept       json
// @Produce      json
// @Param        request  body      api.ScanRequest     true  "Scan request"
// @Success      201      {object}  map[string]string   "job_id"
// @Failure      400      {object}  map[string]string   "error"
// @Failure      500      {object}  map[string]string   "error"
// @Router       /scan [post]
func (h *Handler) ScanHandler(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request body: "+err.Error())
		return
	}

	// Validate target_url.
	if req.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "'target_url' is required")
		return
	}
	if !validateURL(req.TargetURL) {
		writeError(w, http.StatusBadRequest, "'target_url' must be a valid http or https URL")
		return
	}

	// Default and validate scan_profile.
	if req.ScanProfile == "" {
		req.ScanProfile = "passive"
	}
	if !validScanProfiles[req.ScanProfile] {
		writeError(w, http.StatusBadRequest, "'scan_profile' must be one of: passive, active, full")
		return
	}

	// Validate scope entries.
	for _, s := range req.Scope {
		if !validateURL(s) {
			writeError(w, http.StatusBadRequest, "scope entry is not a valid http or https URL: "+s)
			return
		}
	}

	// Validate auth_config is well-formed JSON if provided.
	if len(req.AuthConfig) > 0 {
		var probe any
		if err := json.Unmarshal(req.AuthConfig, &probe); err != nil {
			writeError(w, http.StatusBadRequest, "'auth_config' must be valid JSON: "+err.Error())
			return
		}
	}

	jobID := uuid.NewString()

	msg := &queue.SubmittedMessage{
		JobID:       jobID,
		TargetURL:   req.TargetURL,
		Scope:       req.Scope,
		AuthConfig:  req.AuthConfig,
		ScanProfile: req.ScanProfile,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if msg.Scope == nil {
		msg.Scope = []string{}
	}

	if err := h.publisher.PublishSubmitted(r.Context(), msg); err != nil {
		writeError(w, http.StatusInternalServerError, "publishing to NATS: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"job_id": jobID})
}
