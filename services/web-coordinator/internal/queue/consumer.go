package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	streamName   = "WEBAPP_EVENTS"
	subjectAll   = "webapp.>"
	consumerName = "web-coordinator"

	SubjectSubmitted = "webapp.submitted"

	maxDeliver = 5
)

// SubmittedMessage is published by web-ingestion when a scan has been accepted.
type SubmittedMessage struct {
	JobID       string          `json:"job_id"`
	TargetURL   string          `json:"target_url"`
	Scope       []string        `json:"scope"`
	AuthConfig  json.RawMessage `json:"auth_config,omitempty"`
	ScanProfile string          `json:"scan_profile"`
	SubmittedAt string          `json:"submitted_at"` // RFC3339
}

// MessageHandler handles web pipeline events.
type MessageHandler interface {
	HandleSubmitted(ctx context.Context, msg *SubmittedMessage) error
}

// Consumer subscribes to WEBAPP_EVENTS JetStream and dispatches messages.
type Consumer struct {
	nc      *nats.Conn
	js      jetstream.JetStream
	handler MessageHandler
}

// NewConsumer connects to NATS, ensures the stream exists, and returns a ready Consumer.
func NewConsumer(natsURL string, handler MessageHandler) (*Consumer, error) {
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

	return &Consumer{nc: nc, js: js, handler: handler}, nil
}

// Run starts consuming webapp.submitted messages and blocks until ctx is cancelled.
func (c *Consumer) Run(ctx context.Context) error {
	consumer, err := c.js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       consumerName,
		FilterSubject: SubjectSubmitted,
		MaxDeliver:    maxDeliver,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckWait:       30 * time.Second, // ack happens after DB write + k8s Job creation (seconds, not minutes)
	})
	if err != nil {
		return fmt.Errorf("create submitted consumer: %w", err)
	}

	msgs, err := consumer.Messages()
	if err != nil {
		return fmt.Errorf("get messages iterator: %w", err)
	}
	defer msgs.Stop()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg, err := msgs.Next()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("consumer: error reading message: %v", err)
			continue
		}
		c.handleSubmitted(ctx, msg)
	}
}

func (c *Consumer) handleSubmitted(ctx context.Context, msg jetstream.Msg) {
	var m SubmittedMessage
	if err := json.Unmarshal(msg.Data(), &m); err != nil {
		log.Printf("consumer: failed to unmarshal SubmittedMessage: %v", err)
		_ = msg.Ack() // bad message — don't redeliver
		return
	}
	if err := c.handler.HandleSubmitted(ctx, &m); err != nil {
		log.Printf("consumer: HandleSubmitted error for job %s: %v", m.JobID, err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// Healthy returns true if the underlying NATS connection is live.
func (c *Consumer) Healthy() bool {
	return c.nc != nil && c.nc.IsConnected()
}

// Close shuts down the NATS connection.
func (c *Consumer) Close() {
	c.nc.Close()
}
