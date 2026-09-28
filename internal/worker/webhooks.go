package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/webhook"
)

// SecretSource decrypts an endpoint's signing secret. The service owns the cipher, so the
// worker asks rather than holding the key itself.
type SecretSource interface {
	WebhookSecret(ctx context.Context, endpointID int64) ([]byte, error)
}

// WebhookConfig is how deliveries are attempted.
type WebhookConfig struct {
	// Interval is how often the queue is checked. Short, because a delivery is waiting on
	// it; each check is one indexed query that usually returns nothing.
	Interval time.Duration

	// Timeout bounds one delivery. A receiver that takes longer is treated as down: holding
	// the worker for it would delay every other endpoint's deliveries behind it.
	Timeout time.Duration

	// MaxAttempts is when the panel gives up on a delivery.
	MaxAttempts int

	// Retention is how long delivered rows are kept for an operator to look at.
	Retention time.Duration
}

// Defaults.
const (
	defaultWebhookInterval    = 5 * time.Second
	defaultWebhookTimeout     = 10 * time.Second
	defaultWebhookMaxAttempts = 12
	defaultWebhookRetention   = 7 * 24 * time.Hour

	// webhookBatch bounds one claim. Deliveries are sent one after another, so this is also
	// how long one pass can take in the worst case: batch × timeout.
	webhookBatch = 20

	// Backoff between attempts. The first retry is soon, because the likeliest failure is a
	// receiver restarting; the ceiling keeps a long outage from being hammered.
	webhookBackoffBase = 30 * time.Second
	webhookBackoffMax  = 6 * time.Hour

	// maxErrorBody is how much of a failed response is kept. The status and the start of the
	// body are what diagnose a receiver; the rest is a database filling up with HTML.
	maxErrorBody = 512
)

// Webhooks delivers queued events to their endpoints.
type Webhooks struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	secrets SecretSource
	client  *http.Client
	log     *slog.Logger
	cfg     WebhookConfig
	now     func() time.Time
}

// NewWebhooks builds the delivery worker.
func NewWebhooks(pool *pgxpool.Pool, secrets SecretSource, logger *slog.Logger, cfg WebhookConfig) (*Webhooks, error) {
	if pool == nil || secrets == nil || logger == nil {
		return nil, errors.New("worker: the webhook worker needs a pool, a secret source and a logger")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultWebhookInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultWebhookTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultWebhookMaxAttempts
	}
	if cfg.Retention <= 0 {
		cfg.Retention = defaultWebhookRetention
	}

	client := &http.Client{
		Timeout: cfg.Timeout,
		// Redirects are not followed. A receiver that answers with one has moved or is
		// misconfigured, and following it would send a signed payload somewhere the operator
		// never configured.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return &Webhooks{
		pool:    pool,
		q:       dbgen.New(pool),
		secrets: secrets,
		client:  client,
		log:     logger,
		cfg:     cfg,
		now:     time.Now,
	}, nil
}

// Run checks the queue every interval until ctx is cancelled.
func (w *Webhooks) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	lastCleanup := time.Time{}
	for {
		if _, err := w.Once(ctx); err != nil && ctx.Err() == nil {
			w.log.ErrorContext(ctx, "the webhook delivery pass did not complete", slog.Any("error", err))
		}

		if time.Since(lastCleanup) > time.Hour {
			w.cleanup(ctx)
			lastCleanup = time.Now()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Once claims and delivers one batch, and reports how many were delivered.
func (w *Webhooks) Once(ctx context.Context) (int, error) {
	now := w.now().UTC()

	// The claim bumps each row's attempt count and pushes its next try past this pass. A
	// worker that dies mid-delivery therefore leaves rows that come due again on their own,
	// with the attempt counted — rather than rows retried for ever, or rows lost.
	claimed, err := w.q.ClaimWebhookDeliveries(ctx, dbgen.ClaimWebhookDeliveriesParams{
		MaxAttempts: int32(w.cfg.MaxAttempts),
		Now:         now,
		MaxRows:     webhookBatch,
		RetryAt:     now.Add(webhookBatch*w.cfg.Timeout + time.Minute),
	})
	if err != nil {
		return 0, fmt.Errorf("worker: claim webhook deliveries: %w", err)
	}

	delivered := 0
	for _, delivery := range claimed {
		if ctx.Err() != nil {
			return delivered, ctx.Err()
		}

		err := w.deliver(ctx, delivery)
		if err == nil {
			if markErr := w.q.MarkWebhookDelivered(ctx, dbgen.MarkWebhookDeliveredParams{
				ID:  delivery.ID,
				Now: w.now().UTC(),
			}); markErr != nil {
				// Delivered but not recorded: the receiver will see it again after the
				// lease, which is what the delivery id header exists for.
				w.log.ErrorContext(ctx, "delivered a webhook but could not record it",
					slog.Int64("delivery_id", delivery.ID), slog.Any("error", markErr))
				continue
			}
			delivered++
			continue
		}

		next := w.now().UTC().Add(backoff(int(delivery.Attempts)))
		gaveUp := int(delivery.Attempts) >= w.cfg.MaxAttempts

		logger := w.log.With(
			slog.Int64("delivery_id", delivery.ID),
			slog.Int64("endpoint_id", delivery.EndpointID),
			slog.String("event", delivery.Event),
			slog.Int("attempt", int(delivery.Attempts)),
			slog.Any("error", err))
		if gaveUp {
			logger.ErrorContext(ctx, "giving up on a webhook delivery")
		} else {
			logger.WarnContext(ctx, "a webhook delivery failed; it will be retried", slog.Time("next_try_at", next))
		}

		message := err.Error()
		if len(message) > maxErrorBody {
			message = message[:maxErrorBody]
		}
		if markErr := w.q.MarkWebhookFailed(ctx, dbgen.MarkWebhookFailedParams{
			ID:        delivery.ID,
			LastError: message,
			NextTryAt: next,
		}); markErr != nil {
			w.log.ErrorContext(ctx, "could not record a failed webhook delivery",
				slog.Int64("delivery_id", delivery.ID), slog.Any("error", markErr))
		}
	}

	return delivered, nil
}

// deliver sends one delivery and reports whether the receiver accepted it.
func (w *Webhooks) deliver(ctx context.Context, delivery dbgen.ClaimWebhookDeliveriesRow) error {
	endpoint, err := w.q.GetWebhookEndpoint(ctx, delivery.EndpointID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Deleted since the claim; its deliveries go with it through the cascade.
		return errors.New("the endpoint no longer exists")
	}
	if err != nil {
		return fmt.Errorf("read the endpoint: %w", err)
	}
	if !endpoint.IsEnabled {
		// Kept rather than dropped, so that re-enabling an endpoint delivers what it missed
		// while its attempts last.
		return errors.New("the endpoint is disabled")
	}

	secret, err := w.secrets.WebhookSecret(ctx, delivery.EndpointID)
	if err != nil {
		return fmt.Errorf("read the signing secret: %w", err)
	}

	sentAt := w.now().UTC()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.Url, bytes.NewReader(delivery.Payload))
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "xraypanel-webhook/1")
	request.Header.Set(webhook.HeaderEvent, delivery.Event)
	// The same id on every attempt: a receiver that got the first attempt and whose answer
	// was lost sees the retry as the same delivery and can ignore it.
	request.Header.Set(webhook.HeaderDelivery, strconv.FormatInt(delivery.ID, 10))
	request.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(sentAt.Unix(), 10))
	request.Header.Set(webhook.HeaderSignature, webhook.Sign(secret, delivery.Payload, sentAt))

	response, err := w.client.Do(request)
	if err != nil {
		return fmt.Errorf("post to %s: %w", endpoint.Url, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		// Drained so the connection can be reused, and bounded so a receiver cannot make
		// the panel read an endless response.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		return nil
	}

	excerpt, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))
	return fmt.Errorf("the receiver answered %d: %s", response.StatusCode, bytes.TrimSpace(excerpt))
}

// cleanup forgets delivered history past the retention window.
func (w *Webhooks) cleanup(ctx context.Context) {
	cutoff := w.now().UTC().Add(-w.cfg.Retention)
	rows, err := w.q.DeleteWebhookDeliveriesBefore(ctx, cutoff)
	if err != nil {
		w.log.ErrorContext(ctx, "could not prune delivered webhooks", slog.Any("error", err))
		return
	}
	if rows > 0 {
		w.log.DebugContext(ctx, "pruned delivered webhooks", slog.Int64("rows", rows))
	}
}

// backoff is the delay before the next attempt, doubling from webhookBackoffBase.
func backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := webhookBackoffBase
	for i := 1; i < attempts; i++ {
		delay *= 2
		if delay >= webhookBackoffMax {
			return webhookBackoffMax
		}
	}
	return delay
}
