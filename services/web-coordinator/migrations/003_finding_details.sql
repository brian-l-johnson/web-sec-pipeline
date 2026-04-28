-- Migration 003: tool-specific details as JSONB on web_findings

-- +goose Up

ALTER TABLE web_findings ADD COLUMN details JSONB;

-- +goose Down

ALTER TABLE web_findings DROP COLUMN details;
