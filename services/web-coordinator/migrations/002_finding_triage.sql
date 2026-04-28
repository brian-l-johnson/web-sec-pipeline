-- Migration 002: add triage_status to web_findings

-- +goose Up

ALTER TABLE web_findings
  ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'new'
    CHECK (triage_status IN ('new', 'confirmed', 'false_positive'));

CREATE INDEX idx_web_findings_triage ON web_findings (job_id, triage_status);

-- +goose Down

DROP INDEX IF EXISTS idx_web_findings_triage;
ALTER TABLE web_findings DROP COLUMN triage_status;
