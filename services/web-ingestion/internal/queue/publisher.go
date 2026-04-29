package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	streamName    = "WEBAPP_EVENTS"
	subjectPrefix = "webapp.>"

	SubjectSubmitted = "webapp.submitted"
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

// Publisher wraps a NATS connection and JetStream context.
type Publisher struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// NewPublisher connects to NATS, ensures the WEBAPP_EVENTS stream exists, and
// returns a ready Publisher.
func NewPublisher(natsURL string) (*Publisher, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", natsURL, err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("getting JetStream context: %w", err)
	}

	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:      streamName,
		Subjects:  []string{subjectPrefix},
		Retention: jetstream.LimitsPolicy,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create/update stream %s: %w", streamName, err)
	}

	return &Publisher{nc: nc, js: js}, nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	p.nc.Drain() //nolint:errcheck
}

// PublishSubmitted publishes msg to webapp.submitted.
func (p *Publisher) PublishSubmitted(ctx context.Context, msg *SubmittedMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling SubmittedMessage: %w", err)
	}
	if _, err := p.js.Publish(ctx, SubjectSubmitted, data); err != nil {
		return fmt.Errorf("publishing to %s: %w", SubjectSubmitted, err)
	}
	return nil
}
