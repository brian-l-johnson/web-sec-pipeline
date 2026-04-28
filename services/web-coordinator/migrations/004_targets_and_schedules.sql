-- Migration 004: stored scan targets and periodic schedules

-- +goose Up

CREATE TABLE scan_targets (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    target_url   TEXT        NOT NULL,
    scope        TEXT[]      NOT NULL DEFAULT '{}',
    auth_config  JSONB,
    scan_profile TEXT        NOT NULL DEFAULT 'passive'
                             CHECK (scan_profile IN ('passive','active','full')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_schedules (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id    UUID        NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    cron_expr    TEXT        NOT NULL,
    -- HH:MM in UTC; if set, window_expires_at is computed at launch time
    window_start TEXT,
    window_end   TEXT,
    enabled      BOOLEAN     NOT NULL DEFAULT true,
    last_run_at  TIMESTAMPTZ,
    next_run_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE web_jobs
    ADD COLUMN target_id         UUID        REFERENCES scan_targets(id) ON DELETE SET NULL,
    ADD COLUMN schedule_id       UUID        REFERENCES scan_schedules(id) ON DELETE SET NULL,
    ADD COLUMN window_expires_at TIMESTAMPTZ;

CREATE INDEX idx_scan_schedules_next_run ON scan_schedules (next_run_at) WHERE enabled = true;
CREATE INDEX idx_web_jobs_window         ON web_jobs (window_expires_at) WHERE status = 'running';

-- +goose Down

ALTER TABLE web_jobs
    DROP COLUMN window_expires_at,
    DROP COLUMN schedule_id,
    DROP COLUMN target_id;

DROP TABLE IF EXISTS scan_schedules;
DROP TABLE IF EXISTS scan_targets;
