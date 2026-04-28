package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ScanTarget is a named, reusable scan configuration.
type ScanTarget struct {
	ID          uuid.UUID
	Name        string
	TargetURL   string
	Scope       []string
	AuthConfig  json.RawMessage
	ScanProfile string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ScanSchedule drives periodic execution of a ScanTarget.
type ScanSchedule struct {
	ID          uuid.UUID
	TargetID    uuid.UUID
	CronExpr    string
	WindowStart *string    // "HH:MM" UTC; nil = no window constraint
	WindowEnd   *string    // "HH:MM" UTC; scan is killed after this time
	Enabled     bool
	LastRunAt   *time.Time
	NextRunAt   *time.Time
	CreatedAt   time.Time
}

// ---------------------------------------------------------------------------
// Scan targets
// ---------------------------------------------------------------------------

func (s *Store) CreateTarget(ctx context.Context, t ScanTarget) error {
	var authConfig []byte
	if t.AuthConfig != nil {
		authConfig = []byte(t.AuthConfig)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_targets (id, name, target_url, scope, auth_config, scan_profile)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.Name, t.TargetURL, t.Scope, authConfig, t.ScanProfile,
	)
	if err != nil {
		return fmt.Errorf("create target: %w", err)
	}
	return nil
}

func (s *Store) GetTarget(ctx context.Context, id uuid.UUID) (*ScanTarget, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, target_url, scope, auth_config, scan_profile, created_at, updated_at
		FROM scan_targets WHERE id = $1`, id)
	t, err := scanTarget(row)
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}
	return t, nil
}

func (s *Store) ListTargets(ctx context.Context) ([]ScanTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, target_url, scope, auth_config, scan_profile, created_at, updated_at
		FROM scan_targets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()
	var targets []ScanTarget
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		targets = append(targets, *t)
	}
	return targets, rows.Err()
}

func (s *Store) UpdateTarget(ctx context.Context, t ScanTarget) error {
	var authConfig []byte
	if t.AuthConfig != nil {
		authConfig = []byte(t.AuthConfig)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_targets
		SET name=$2, target_url=$3, scope=$4, auth_config=$5, scan_profile=$6, updated_at=NOW()
		WHERE id=$1`,
		t.ID, t.Name, t.TargetURL, t.Scope, authConfig, t.ScanProfile,
	)
	if err != nil {
		return fmt.Errorf("update target: %w", err)
	}
	return nil
}

func (s *Store) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM scan_targets WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete target: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scan schedules
// ---------------------------------------------------------------------------

func (s *Store) CreateSchedule(ctx context.Context, sc ScanSchedule) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_schedules
			(id, target_id, cron_expr, window_start, window_end, enabled, next_run_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sc.ID, sc.TargetID, sc.CronExpr, sc.WindowStart, sc.WindowEnd,
		sc.Enabled, sc.NextRunAt,
	)
	if err != nil {
		return fmt.Errorf("create schedule: %w", err)
	}
	return nil
}

func (s *Store) GetSchedule(ctx context.Context, id uuid.UUID) (*ScanSchedule, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, target_id, cron_expr, window_start, window_end, enabled,
		       last_run_at, next_run_at, created_at
		FROM scan_schedules WHERE id=$1`, id)
	sc, err := scanSchedule(row)
	if err != nil {
		return nil, fmt.Errorf("get schedule: %w", err)
	}
	return sc, nil
}

func (s *Store) ListSchedules(ctx context.Context, targetID uuid.UUID) ([]ScanSchedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, target_id, cron_expr, window_start, window_end, enabled,
		       last_run_at, next_run_at, created_at
		FROM scan_schedules WHERE target_id=$1 ORDER BY created_at`, targetID)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()
	var schedules []ScanSchedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		schedules = append(schedules, *sc)
	}
	return schedules, rows.Err()
}

func (s *Store) UpdateSchedule(ctx context.Context, sc ScanSchedule) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_schedules
		SET cron_expr=$2, window_start=$3, window_end=$4, enabled=$5, next_run_at=$6
		WHERE id=$1`,
		sc.ID, sc.CronExpr, sc.WindowStart, sc.WindowEnd, sc.Enabled, sc.NextRunAt,
	)
	if err != nil {
		return fmt.Errorf("update schedule: %w", err)
	}
	return nil
}

func (s *Store) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM scan_schedules WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete schedule: %w", err)
	}
	return nil
}

// SetScheduleEnabled toggles the enabled flag and, if enabling, recomputes
// next_run_at from the supplied value.
func (s *Store) SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool, nextRunAt *time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_schedules SET enabled=$2, next_run_at=$3 WHERE id=$1`,
		id, enabled, nextRunAt,
	)
	if err != nil {
		return fmt.Errorf("set schedule enabled: %w", err)
	}
	return nil
}

// ListDueSchedules returns enabled schedules whose next_run_at is in the past.
func (s *Store) ListDueSchedules(ctx context.Context) ([]ScanSchedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, target_id, cron_expr, window_start, window_end, enabled,
		       last_run_at, next_run_at, created_at
		FROM scan_schedules
		WHERE enabled = true AND next_run_at <= NOW()
		ORDER BY next_run_at`)
	if err != nil {
		return nil, fmt.Errorf("list due schedules: %w", err)
	}
	defer rows.Close()
	var schedules []ScanSchedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan due schedule: %w", err)
		}
		schedules = append(schedules, *sc)
	}
	return schedules, rows.Err()
}

// UpdateScheduleRunTimes records last_run_at and advances next_run_at.
func (s *Store) UpdateScheduleRunTimes(ctx context.Context, id uuid.UUID, lastRun time.Time, nextRun time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_schedules SET last_run_at=$2, next_run_at=$3 WHERE id=$1`,
		id, lastRun, nextRun,
	)
	if err != nil {
		return fmt.Errorf("update schedule run times: %w", err)
	}
	return nil
}

// ListRunningJobsExceedingWindow returns running jobs whose scan window has expired.
func (s *Store) ListRunningJobsExceedingWindow(ctx context.Context) ([]WebJob, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, status, target_url, scope, auth_config, scan_profile,
		       submitted_at, started_at, completed_at, error, har_path,
		       crawl_status, zap_status, nuclei_status,
		       target_id, schedule_id, window_expires_at
		FROM web_jobs
		WHERE status = 'running'
		  AND window_expires_at IS NOT NULL
		  AND window_expires_at < NOW()`)
	if err != nil {
		return nil, fmt.Errorf("list jobs exceeding window: %w", err)
	}
	defer rows.Close()
	var jobs []WebJob
	for rows.Next() {
		job, err := scanJobFull(rows)
		if err != nil {
			return nil, fmt.Errorf("scan job: %w", err)
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

// ---------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------

func scanTarget(row pgx.Row) (*ScanTarget, error) {
	var t ScanTarget
	var authBytes []byte
	err := row.Scan(
		&t.ID, &t.Name, &t.TargetURL, &t.Scope, &authBytes,
		&t.ScanProfile, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if authBytes != nil {
		t.AuthConfig = json.RawMessage(authBytes)
	}
	return &t, nil
}

func scanSchedule(row pgx.Row) (*ScanSchedule, error) {
	var sc ScanSchedule
	err := row.Scan(
		&sc.ID, &sc.TargetID, &sc.CronExpr, &sc.WindowStart, &sc.WindowEnd,
		&sc.Enabled, &sc.LastRunAt, &sc.NextRunAt, &sc.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}
