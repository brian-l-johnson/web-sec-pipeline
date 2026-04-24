-- Migration 001: initial schema for web-sec-tools pipeline

-- +goose Up

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- web_jobs
-- Tracks one scan pipeline run per submitted target URL.
-- ---------------------------------------------------------------------------
CREATE TABLE web_jobs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','running','complete','failed')),
    target_url      TEXT        NOT NULL,
    scope           TEXT[]      NOT NULL DEFAULT '{}',
    auth_config     JSONB,
    scan_profile    TEXT        NOT NULL DEFAULT 'passive'
                                CHECK (scan_profile IN ('passive','active','full')),

    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error           TEXT,

    -- Per-tool status columns mirror the pattern in android-re-pipeline.
    -- crawl must complete before zap/nuclei are launched.
    crawl_status    TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (crawl_status IN ('pending','running','complete','failed')),
    zap_status      TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (zap_status IN ('pending','running','complete','failed')),
    nuclei_status   TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (nuclei_status IN ('pending','running','complete','failed')),

    -- Path on the shared PVC where the mitmproxy HAR capture was written.
    har_path        TEXT
);

CREATE INDEX idx_web_jobs_status      ON web_jobs (status);
CREATE INDEX idx_web_jobs_submitted   ON web_jobs (submitted_at DESC);

-- ---------------------------------------------------------------------------
-- web_findings
-- One row per finding emitted by ZAP or Nuclei for a given job.
-- ---------------------------------------------------------------------------
CREATE TABLE web_findings (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID        NOT NULL REFERENCES web_jobs (id) ON DELETE CASCADE,
    tool            TEXT        NOT NULL CHECK (tool IN ('zap','nuclei')),
    severity        TEXT        NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    title           TEXT        NOT NULL,
    url             TEXT        NOT NULL,
    description     TEXT,
    evidence        TEXT,       -- request/response snippet
    cwe             INT,
    template_id     TEXT,       -- Nuclei template ID; NULL for ZAP findings
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_web_findings_job_id  ON web_findings (job_id);
CREATE INDEX idx_web_findings_tool    ON web_findings (job_id, tool);
CREATE INDEX idx_web_findings_severity ON web_findings (severity);

-- +goose Down

DROP TABLE IF EXISTS web_findings;
DROP TABLE IF EXISTS web_jobs;
