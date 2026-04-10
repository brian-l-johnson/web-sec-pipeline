package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
)

const (
	streamName    = "WEBAPP_EVENTS"
	subjectPrefix = "webapp.>"

	SubjectSubmitted = "webapp.submitted"
	SubjectFailed    = "webapp.ingestion.failed"
)

// SubmittedMessage is published to webapp.submitted when a scan has been
// validated and accepted.
type SubmittedMessage struct {
	JobID       string          `json:"job_id"`
	TargetURL   string          `json:"target_url"`
	Scope       []string        `json:"scope"`
	AuthConfig  json.RawMessage `json:"auth_config,omitempty"`
	ScanProfile string          `json:"scan_profile"`
	SubmittedAt string          `json:"submitted_at"` // RFC3339
}

// FailedMessage is published to webapp.ingestion.failed when ingestion fails.
type FailedMessage struct {
	JobID string `json:"job_id"`
	Error string `json:"error"`
}

// Publisher wraps a NATS connection and JetStream context.
type Publisher struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

// NewPublisher connects to NATS, ensures the WEBAPP_EVENTS stream exists, and
// returns a ready Publisher.
func NewPublisher(natsURL string) (*Publisher, error) {
	conn, err := nats.Connect(natsURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", natsURL, err)
	}

	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("getting JetStream context: %w", err)
	}

	_, err = js.StreamInfo(streamName)
	if err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{subjectPrefix},
			Retention: nats.WorkQueuePolicy,
		})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("creating stream %s: %w", streamName, err)
		}
	}

	return &Publisher{conn: conn, js: js}, nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	p.conn.Drain() //nolint:errcheck
}

// PublishSubmitted publishes msg to webapp.submitted.
func (p *Publisher) PublishSubmitted(_ context.Context, msg *SubmittedMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling SubmittedMessage: %w", err)
	}
	if _, err := p.js.Publish(SubjectSubmitted, data); err != nil {
		return fmt.Errorf("publishing to %s: %w", SubjectSubmitted, err)
	}
	return nil
}

// PublishFailed publishes msg to webapp.ingestion.failed.
func (p *Publisher) PublishFailed(_ context.Context, msg *FailedMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling FailedMessage: %w", err)
	}
	if _, err := p.js.Publish(SubjectFailed, data); err != nil {
		return fmt.Errorf("publishing to %s: %w", SubjectFailed, err)
	}
	return nil
}
