package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WebJob represents a row in the web_jobs table.
type WebJob struct {
	ID           uuid.UUID
	Status       string // pending, running, complete, failed
	TargetURL    string
	Scope        []string
	AuthConfig   json.RawMessage // nullable
	ScanProfile  string          // passive, active, full
	SubmittedAt  time.Time
	StartedAt    *time.Time
	CompletedAt  *time.Time
	Error        *string
	HARPath      *string
	CrawlStatus  string
	ZAPStatus    string
	NucleiStatus string
}

// WebFinding represents a row in the web_findings table.
type WebFinding struct {
	ID          uuid.UUID
	JobID       uuid.UUID
	Tool        string // zap, nuclei
	Severity    string // info, low, medium, high, critical
	Title       string
	URL         string
	Description *string
	Evidence    *string
	CWE         *int
	TemplateID  *string
	CreatedAt   time.Time
}

// CreateJob inserts a new job into the database.
func (s *Store) CreateJob(ctx context.Context, job WebJob) error {
	var authConfig []byte
	if job.AuthConfig != nil {
		authConfig = []byte(job.AuthConfig)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO web_jobs (
			id, status, target_url, scope, auth_config, scan_profile,
			submitted_at, crawl_status, zap_status, nuclei_status
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10
		)`,
		job.ID, job.Status, job.TargetURL, job.Scope, authConfig, job.ScanProfile,
		job.SubmittedAt, job.CrawlStatus, job.ZAPStatus, job.NucleiStatus,
	)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	return nil
}

// GetJob retrieves a job by its ID.
func (s *Store) GetJob(ctx context.Context, jobID uuid.UUID) (*WebJob, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, status, target_url, scope, auth_config, scan_profile,
		       submitted_at, started_at, completed_at, error, har_path,
		       crawl_status, zap_status, nuclei_status
		FROM web_jobs
		WHERE id = $1`,
		jobID,
	)
	job, err := scanJob(row)
	if err != nil {
		return nil, fmt.Errorf("get job: %w", err)
	}
	return job, nil
}

// ListJobs returns jobs ordered by submitted_at DESC with pagination.
func (s *Store) ListJobs(ctx context.Context, limit, offset int) ([]WebJob, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, status, target_url, scope, auth_config, scan_profile,
		       submitted_at, started_at, completed_at, error, har_path,
		       crawl_status, zap_status, nuclei_status
		FROM web_jobs
		ORDER BY submitted_at DESC
		LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	var jobs []WebJob
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan job: %w", err)
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

// CountJobs returns the total number of jobs in the database.
func (s *Store) CountJobs(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM web_jobs`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count jobs: %w", err)
	}
	return count, nil
}

// ListRunningJobs returns all jobs in the "running" state (for reconciliation on startup).
func (s *Store) ListRunningJobs(ctx context.Context) ([]WebJob, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, status, target_url, scope, auth_config, scan_profile,
		       submitted_at, started_at, completed_at, error, har_path,
		       crawl_status, zap_status, nuclei_status
		FROM web_jobs
		WHERE status = 'running'`,
	)
	if err != nil {
		return nil, fmt.Errorf("list running jobs: %w", err)
	}
	defer rows.Close()

	var jobs []WebJob
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan running job: %w", err)
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

// UpdateJobStatus updates the overall status of a job.
func (s *Store) UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE web_jobs SET status = $2 WHERE id = $1`,
		jobID, status,
	)
	if err != nil {
		return fmt.Errorf("update job status: %w", err)
	}
	return nil
}

// UpdateJobToolStatus updates crawl_status, zap_status, or nuclei_status.
func (s *Store) UpdateJobToolStatus(ctx context.Context, jobID uuid.UUID, tool, status string) error {
	var col string
	switch tool {
	case "crawl":
		col = "crawl_status"
	case "zap":
		col = "zap_status"
	case "nuclei":
		col = "nuclei_status"
	default:
		return fmt.Errorf("unknown tool: %s", tool)
	}
	query := fmt.Sprintf(`UPDATE web_jobs SET %s = $2 WHERE id = $1`, col)
	_, err := s.pool.Exec(ctx, query, jobID, status)
	if err != nil {
		return fmt.Errorf("update tool status (%s): %w", tool, err)
	}
	return nil
}

// SetJobStarted marks a job as running and records started_at.
func (s *Store) SetJobStarted(ctx context.Context, jobID uuid.UUID) error {
	now := time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE web_jobs SET status = 'running', started_at = $2 WHERE id = $1`,
		jobID, now,
	)
	if err != nil {
		return fmt.Errorf("set job started: %w", err)
	}
	return nil
}

// SetJobCompleted marks a job as complete and records completed_at.
func (s *Store) SetJobCompleted(ctx context.Context, jobID uuid.UUID) error {
	now := time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE web_jobs SET status = 'complete', completed_at = $2 WHERE id = $1`,
		jobID, now,
	)
	if err != nil {
		return fmt.Errorf("set job completed: %w", err)
	}
	return nil
}

// SetJobError marks a job as failed with the given error message.
func (s *Store) SetJobError(ctx context.Context, jobID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE web_jobs SET status = 'failed', error = $2 WHERE id = $1`,
		jobID, errMsg,
	)
	if err != nil {
		return fmt.Errorf("set job error: %w", err)
	}
	return nil
}

// SetHARPath stores the path to the captured HAR file for a job.
func (s *Store) SetHARPath(ctx context.Context, jobID uuid.UUID, harPath string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE web_jobs SET har_path = $2 WHERE id = $1`,
		jobID, harPath,
	)
	if err != nil {
		return fmt.Errorf("set har path: %w", err)
	}
	return nil
}

// ResetJobForRetrigger resets a job back to running with all tool statuses pending.
func (s *Store) ResetJobForRetrigger(ctx context.Context, jobID uuid.UUID) error {
	now := time.Now()
	_, err := s.pool.Exec(ctx, `
		UPDATE web_jobs SET
			status        = 'running',
			started_at    = $2,
			completed_at  = NULL,
			error         = NULL,
			har_path      = NULL,
			crawl_status  = 'running',
			zap_status    = 'pending',
			nuclei_status = 'pending'
		WHERE id = $1`,
		jobID, now,
	)
	if err != nil {
		return fmt.Errorf("reset job for retrigger: %w", err)
	}
	return nil
}

// InsertFinding inserts a single finding row.
func (s *Store) InsertFinding(ctx context.Context, f WebFinding) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO web_findings (
			id, job_id, tool, severity, title, url,
			description, evidence, cwe, template_id
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10
		)`,
		f.ID, f.JobID, f.Tool, f.Severity, f.Title, f.URL,
		f.Description, f.Evidence, f.CWE, f.TemplateID,
	)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

// ListFindings returns all findings for a given job, ordered by severity then tool.
func (s *Store) ListFindings(ctx context.Context, jobID uuid.UUID) ([]WebFinding, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, job_id, tool, severity, title, url,
		       description, evidence, cwe, template_id, created_at
		FROM web_findings
		WHERE job_id = $1
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high'     THEN 2
				WHEN 'medium'   THEN 3
				WHEN 'low'      THEN 4
				WHEN 'info'     THEN 5
				ELSE 6
			END,
			tool, title`,
		jobID,
	)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []WebFinding
	for rows.Next() {
		var f WebFinding
		if err := rows.Scan(
			&f.ID, &f.JobID, &f.Tool, &f.Severity, &f.Title, &f.URL,
			&f.Description, &f.Evidence, &f.CWE, &f.TemplateID, &f.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// scanJob scans a single web_jobs row from a pgx.Row or pgx.Rows.
func scanJob(row pgx.Row) (*WebJob, error) {
	var job WebJob
	var authConfigBytes []byte

	err := row.Scan(
		&job.ID, &job.Status, &job.TargetURL, &job.Scope, &authConfigBytes, &job.ScanProfile,
		&job.SubmittedAt, &job.StartedAt, &job.CompletedAt, &job.Error, &job.HARPath,
		&job.CrawlStatus, &job.ZAPStatus, &job.NucleiStatus,
	)
	if err != nil {
		return nil, err
	}
	if authConfigBytes != nil {
		job.AuthConfig = json.RawMessage(authConfigBytes)
	}
	return &job, nil
}
