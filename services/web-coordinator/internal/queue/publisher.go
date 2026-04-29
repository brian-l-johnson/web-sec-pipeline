package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	SubjectJobStarted   = "webapp.job.started"
	SubjectJobCompleted = "webapp.job.completed"
	SubjectJobFailed    = "webapp.job.failed"
)

// JobStartedMessage is published to webapp.job.started when a scan begins.
type JobStartedMessage struct {
	JobID     string `json:"job_id"`
	TargetURL string `json:"target_url"`
	Profile   string `json:"scan_profile"`
	StartedAt string `json:"started_at"` // RFC3339
}

// JobCompletedMessage is published to webapp.job.completed when a scan finishes successfully.
type JobCompletedMessage struct {
	JobID        string `json:"job_id"`
	TargetURL    string `json:"target_url"`
	CompletedAt  string `json:"completed_at"` // RFC3339
	ZAPStatus    string `json:"zap_status"`
	NucleiStatus string `json:"nuclei_status"`
}

// JobFailedMessage is published to webapp.job.failed when a scan fails terminally.
type JobFailedMessage struct {
	JobID     string `json:"job_id"`
	TargetURL string `json:"target_url"`
	FailedAt  string `json:"failed_at"` // RFC3339
	Reason    string `json:"reason"`
}

// Publisher publishes pipeline-stage events to NATS JetStream.
type Publisher struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// NewPublisher connects to NATS, ensures the WEBAPP_EVENTS stream exists, and
// returns a ready Publisher.
func NewPublisher(natsURL string) (*Publisher, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, fmt.Errorf("connect to nats: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create jetstream context: %w", err)
	}

	_, err = js.CreateOrUpdateStream(context.Background(), jetstream.StreamConfig{
		Name:      streamName,
		Subjects:  []string{subjectAll},
		Retention: jetstream.LimitsPolicy,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create/update stream: %w", err)
	}

	return &Publisher{nc: nc, js: js}, nil
}

// Close shuts down the NATS connection.
func (p *Publisher) Close() {
	p.nc.Close()
}

// PublishJobStarted publishes msg to webapp.job.started.
func (p *Publisher) PublishJobStarted(ctx context.Context, msg *JobStartedMessage) error {
	return p.publish(ctx, SubjectJobStarted, msg)
}

// PublishJobCompleted publishes msg to webapp.job.completed.
func (p *Publisher) PublishJobCompleted(ctx context.Context, msg *JobCompletedMessage) error {
	return p.publish(ctx, SubjectJobCompleted, msg)
}

// PublishJobFailed publishes msg to webapp.job.failed.
func (p *Publisher) PublishJobFailed(ctx context.Context, msg *JobFailedMessage) error {
	return p.publish(ctx, SubjectJobFailed, msg)
}

func (p *Publisher) publish(ctx context.Context, subject string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	if _, err := p.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}
	return nil
}
