package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/jobs"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/queue"
	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// Orchestrator implements queue.MessageHandler and jobs.JobEventHandler.
// It ties together the NATS consumer, k8s job manager, and store into the
// full web scan pipeline.
type Orchestrator struct {
	store   *store.Store
	manager *jobs.Manager
	dataDir string
}

// NewOrchestrator creates an Orchestrator with all its dependencies.
func NewOrchestrator(s *store.Store, m *jobs.Manager, dataDir string) *Orchestrator {
	return &Orchestrator{store: s, manager: m, dataDir: dataDir}
}

// Compile-time interface assertions.
var _ queue.MessageHandler = (*Orchestrator)(nil)
var _ jobs.JobEventHandler = (*Orchestrator)(nil)

// ---------------------------------------------------------------------------
// queue.MessageHandler implementation
// ---------------------------------------------------------------------------

// HandleSubmitted processes a webapp.submitted NATS message.
func (o *Orchestrator) HandleSubmitted(ctx context.Context, msg *queue.SubmittedMessage) error {
	jobID, err := uuid.Parse(msg.JobID)
	if err != nil {
		return fmt.Errorf("invalid job_id %q: %w", msg.JobID, err)
	}

	submittedAt, err := time.Parse(time.RFC3339, msg.SubmittedAt)
	if err != nil {
		submittedAt = time.Now()
	}

	job := store.WebJob{
		ID:           jobID,
		Status:       "running",
		TargetURL:    msg.TargetURL,
		Scope:        msg.Scope,
		AuthConfig:   msg.AuthConfig,
		ScanProfile:  msg.ScanProfile,
		SubmittedAt:  submittedAt,
		CrawlStatus:  "running",
		ZAPStatus:    "pending",
		NucleiStatus: "pending",
	}
	if job.Scope == nil {
		job.Scope = []string{}
	}

	if err := o.store.CreateJob(ctx, job); err != nil {
		return fmt.Errorf("create job in db: %w", err)
	}

	now := time.Now()
	if err := o.store.SetJobStarted(ctx, jobID); err != nil {
		log.Printf("orchestrator: set job started failed (job=%s): %v", jobID, err)
	}
	_ = now

	if err := o.manager.CreateCrawlJob(ctx, jobID, msg.TargetURL, msg.Scope, msg.AuthConfig); err != nil {
		_ = o.store.SetJobError(ctx, jobID, fmt.Sprintf("create crawl job: %v", err))
		return fmt.Errorf("create crawl job: %w", err)
	}

	log.Printf("orchestrator: job %s started (target=%s profile=%s)", jobID, msg.TargetURL, msg.ScanProfile)
	return nil
}

// HandleIngestionFailed processes a webapp.ingestion.failed NATS message.
func (o *Orchestrator) HandleIngestionFailed(ctx context.Context, msg *queue.FailedMessage) error {
	jobID, err := uuid.Parse(msg.JobID)
	if err != nil {
		return fmt.Errorf("invalid job_id %q: %w", msg.JobID, err)
	}
	if err := o.store.SetJobError(ctx, jobID, msg.Error); err != nil {
		return fmt.Errorf("set job error: %w", err)
	}
	log.Printf("orchestrator: job %s ingestion failed: %s", jobID, msg.Error)
	return nil
}

// ---------------------------------------------------------------------------
// jobs.JobEventHandler implementation
// ---------------------------------------------------------------------------

// OnJobComplete is called when a crawler, ZAP, or Nuclei k8s Job completes.
func (o *Orchestrator) OnJobComplete(jobID uuid.UUID, tool string) {
	ctx := context.Background()

	if err := o.store.UpdateJobToolStatus(ctx, jobID, tool, "complete"); err != nil {
		log.Printf("orchestrator: update tool status failed (job=%s tool=%s): %v", jobID, tool, err)
		return
	}
	log.Printf("orchestrator: tool %s complete for job %s", tool, jobID)

	switch tool {
	case "crawl":
		harPath := fmt.Sprintf("%s/output/%s/crawl/capture.har", o.dataDir, jobID)
		if err := o.store.SetHARPath(ctx, jobID, harPath); err != nil {
			log.Printf("orchestrator: set har path failed (job=%s): %v", jobID, err)
		}
		o.launchScanners(ctx, jobID)

	case "zap":
		reportPath := fmt.Sprintf("%s/output/%s/zap/report.json", o.dataDir, jobID)
		if err := o.parseAndStoreZAPFindings(ctx, jobID, reportPath); err != nil {
			log.Printf("orchestrator: zap findings parse error (job=%s): %v", jobID, err)
		}
		o.checkAndCompleteJob(ctx, jobID)

	case "nuclei":
		reportPath := fmt.Sprintf("%s/output/%s/nuclei/nuclei.jsonl", o.dataDir, jobID)
		if err := o.parseAndStoreNucleiFindings(ctx, jobID, reportPath); err != nil {
			log.Printf("orchestrator: nuclei findings parse error (job=%s): %v", jobID, err)
		}
		o.checkAndCompleteJob(ctx, jobID)
	}
}

// OnJobFailed is called when a k8s Job fails.
func (o *Orchestrator) OnJobFailed(jobID uuid.UUID, tool string, logs string) {
	ctx := context.Background()

	if err := o.store.UpdateJobToolStatus(ctx, jobID, tool, "failed"); err != nil {
		log.Printf("orchestrator: update tool status failed (job=%s tool=%s): %v", jobID, tool, err)
	}

	if tool == "crawl" {
		// Crawl failure is terminal — no point running ZAP/Nuclei.
		errMsg := fmt.Sprintf("crawl: %s", logs)
		if err := o.store.SetJobError(ctx, jobID, errMsg); err != nil {
			log.Printf("orchestrator: set job error failed (job=%s): %v", jobID, err)
		}
		log.Printf("orchestrator: crawl failed for job %s: %s", jobID, logs)
		return
	}

	// ZAP or Nuclei failure — log it but don't fail the whole job;
	// checkAndCompleteJob will mark the job complete once both are settled.
	log.Printf("orchestrator: tool %s failed for job %s: %s", tool, jobID, logs)
	o.checkAndCompleteJob(ctx, jobID)
}

// SubmitJob creates and immediately starts a new scan job.
// Called directly by the web UI API endpoint (bypasses NATS).
func (o *Orchestrator) SubmitJob(ctx context.Context, targetURL string, scope []string, authConfig json.RawMessage, scanProfile string) (uuid.UUID, error) {
	jobID := uuid.New()
	msg := &queue.SubmittedMessage{
		JobID:       jobID.String(),
		TargetURL:   targetURL,
		Scope:       scope,
		AuthConfig:  authConfig,
		ScanProfile: scanProfile,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := o.HandleSubmitted(ctx, msg); err != nil {
		return uuid.Nil, err
	}
	return jobID, nil
}

// RetriggerJob resets a job and re-launches the crawl.
func (o *Orchestrator) RetriggerJob(ctx context.Context, job *store.WebJob) error {
	if job.Status == "running" {
		return fmt.Errorf("job is already running")
	}
	if err := o.store.ResetJobForRetrigger(ctx, job.ID); err != nil {
		return fmt.Errorf("reset job: %w", err)
	}
	if err := o.manager.CreateCrawlJob(ctx, job.ID, job.TargetURL, job.Scope, job.AuthConfig); err != nil {
		_ = o.store.SetJobError(ctx, job.ID, fmt.Sprintf("retrigger: create crawl job: %v", err))
		return fmt.Errorf("create crawl job: %w", err)
	}
	log.Printf("orchestrator: job %s retriggered", job.ID)
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// launchScanners starts ZAP and Nuclei Jobs in parallel after a successful crawl.
// Failures are logged but do not abort the other scanner.
func (o *Orchestrator) launchScanners(ctx context.Context, jobID uuid.UUID) {
	job, err := o.store.GetJob(ctx, jobID)
	if err != nil {
		log.Printf("orchestrator: get job failed before launching scanners (job=%s): %v", jobID, err)
		return
	}

	go func() {
		if err := o.store.UpdateJobToolStatus(ctx, jobID, "zap", "running"); err != nil {
			log.Printf("orchestrator: set zap running (job=%s): %v", jobID, err)
		}
		if err := o.manager.CreateZAPJob(ctx, jobID, job.TargetURL, job.ScanProfile); err != nil {
			log.Printf("orchestrator: create zap job failed (job=%s): %v", jobID, err)
			_ = o.store.UpdateJobToolStatus(ctx, jobID, "zap", "failed")
			o.checkAndCompleteJob(ctx, jobID)
		}
	}()

	go func() {
		if err := o.store.UpdateJobToolStatus(ctx, jobID, "nuclei", "running"); err != nil {
			log.Printf("orchestrator: set nuclei running (job=%s): %v", jobID, err)
		}
		if err := o.manager.CreateNucleiJob(ctx, jobID, job.TargetURL); err != nil {
			log.Printf("orchestrator: create nuclei job failed (job=%s): %v", jobID, err)
			_ = o.store.UpdateJobToolStatus(ctx, jobID, "nuclei", "failed")
			o.checkAndCompleteJob(ctx, jobID)
		}
	}()
}

// checkAndCompleteJob marks the overall job complete when both ZAP and Nuclei
// have settled (complete or failed). One scanner failing does not block the other.
func (o *Orchestrator) checkAndCompleteJob(ctx context.Context, jobID uuid.UUID) {
	job, err := o.store.GetJob(ctx, jobID)
	if err != nil {
		log.Printf("orchestrator: get job failed in checkAndComplete (job=%s): %v", jobID, err)
		return
	}

	zapDone := job.ZAPStatus == "complete" || job.ZAPStatus == "failed"
	nucleiDone := job.NucleiStatus == "complete" || job.NucleiStatus == "failed"

	if zapDone && nucleiDone {
		if err := o.store.SetJobCompleted(ctx, jobID); err != nil {
			log.Printf("orchestrator: set job completed failed (job=%s): %v", jobID, err)
		} else {
			log.Printf("orchestrator: job %s complete (zap=%s nuclei=%s)", jobID, job.ZAPStatus, job.NucleiStatus)
		}
	}
}
