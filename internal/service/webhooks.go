package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/crypto"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// The events the panel emits. Deliberately few and about one thing each: a receiver should
// be able to act on an event without asking the panel a follow-up question, and should not
// have to filter a firehose to find the two it cares about.
const (
	EventUserCreated = "user.created"
	EventUserLimited = "user.limited"
	EventUserExpired = "user.expired"
	EventUserRenewed = "user.renewed"
)

// KnownWebhookEvents is what an endpoint may subscribe to.
var KnownWebhookEvents = []string{
	EventUserCreated,
	EventUserLimited,
	EventUserExpired,
	EventUserRenewed,
}

// purposeWebhookSecret binds a webhook secret's ciphertext to its role, so a value moved
// from another column cannot be decrypted as one.
const purposeWebhookSecret = "webhook.secret"

// webhookSecretBytes is the length of a generated signing secret.
const webhookSecretBytes = 32

// CreateWebhookEndpointInput is a new subscriber to the panel's events.
type CreateWebhookEndpointInput struct {
	URL    string
	Events []string

	// Secret signs deliveries. Empty means the panel generates one, which is the normal
	// case: a secret the operator typed is a secret that has been in a shell history.
	Secret string

	Enabled bool
}

// WebhookEndpoint is an endpoint as the API reports it.
type WebhookEndpoint struct {
	ID        int64
	URL       string
	Events    []string
	Enabled   bool
	CreatedAt time.Time

	// Secret is returned only by Create, and only when the panel generated it. It cannot be
	// read back afterwards: it is stored encrypted, and an endpoint listing that handed out
	// signing secrets would make a read-only token enough to forge deliveries.
	Secret string
}

// CreateWebhookEndpoint registers a receiver for events.
func (s *Service) CreateWebhookEndpoint(
	ctx context.Context, actor audit.Actor, in CreateWebhookEndpointInput,
) (*WebhookEndpoint, error) {
	if err := validateWebhookURL(in.URL); err != nil {
		return nil, err
	}

	events, err := validateWebhookEvents(in.Events)
	if err != nil {
		return nil, err
	}

	secret := in.Secret
	generated := false
	if strings.TrimSpace(secret) == "" {
		secret, err = crypto.RandomToken(webhookSecretBytes)
		if err != nil {
			return nil, fmt.Errorf("service: generate a webhook secret: %w", err)
		}
		generated = true
	}

	sealed, err := s.cipher.Encrypt([]byte(secret), purposeWebhookSecret)
	if err != nil {
		return nil, fmt.Errorf("service: encrypt the webhook secret: %w", err)
	}

	var created dbgen.WebhookEndpoint
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		endpoint, err := queries.CreateWebhookEndpoint(ctx, dbgen.CreateWebhookEndpointParams{
			Url:       in.URL,
			SecretEnc: sealed,
			Events:    events,
			IsEnabled: in.Enabled,
		})
		if err != nil {
			return translate(err, "webhook endpoint")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "webhook.create",
			EntityType: "webhook_endpoint",
			EntityID:   fmt.Sprint(endpoint.ID),
			// The URL is recorded; the secret is not, and neither is anything derived from
			// it. An audit log is read by more people than can be trusted with a signing key.
			After: map[string]any{"url": endpoint.Url, "events": events, "enabled": endpoint.IsEnabled},
		})

		created = endpoint
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := webhookEndpointOf(created)
	if generated {
		result.Secret = secret
	}
	return result, nil
}

// ListWebhookEndpoints returns every endpoint, without secrets.
func (s *Service) ListWebhookEndpoints(ctx context.Context) ([]WebhookEndpoint, error) {
	rows, err := s.q.ListWebhookEndpoints(ctx)
	if err != nil {
		return nil, translate(err, "webhook endpoints")
	}

	endpoints := make([]WebhookEndpoint, 0, len(rows))
	for _, row := range rows {
		endpoints = append(endpoints, *webhookEndpointOf(row))
	}
	return endpoints, nil
}

// UpdateWebhookEndpointInput changes an endpoint. Nil leaves a field alone.
type UpdateWebhookEndpointInput struct {
	URL     *string
	Events  *[]string
	Enabled *bool
}

// UpdateWebhookEndpoint changes where and what an endpoint receives.
func (s *Service) UpdateWebhookEndpoint(
	ctx context.Context, actor audit.Actor, id int64, in UpdateWebhookEndpointInput,
) (*WebhookEndpoint, error) {
	if in.URL != nil {
		if err := validateWebhookURL(*in.URL); err != nil {
			return nil, err
		}
	}

	var events []string
	if in.Events != nil {
		validated, err := validateWebhookEvents(*in.Events)
		if err != nil {
			return nil, err
		}
		events = validated
	}

	var updated dbgen.WebhookEndpoint
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetWebhookEndpoint(ctx, id)
		if err != nil {
			return translate(err, "webhook endpoint")
		}

		endpoint, err := queries.UpdateWebhookEndpoint(ctx, dbgen.UpdateWebhookEndpointParams{
			ID:        id,
			Url:       in.URL,
			Events:    events,
			IsEnabled: in.Enabled,
		})
		if err != nil {
			return translate(err, "webhook endpoint")
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "webhook.update",
			EntityType: "webhook_endpoint",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"url": before.Url, "events": before.Events, "enabled": before.IsEnabled},
			After:      map[string]any{"url": endpoint.Url, "events": endpoint.Events, "enabled": endpoint.IsEnabled},
		})

		updated = endpoint
		return nil
	})
	if err != nil {
		return nil, err
	}
	return webhookEndpointOf(updated), nil
}

// DeleteWebhookEndpoint removes an endpoint and its queued deliveries.
func (s *Service) DeleteWebhookEndpoint(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetWebhookEndpoint(ctx, id)
		if err != nil {
			return translate(err, "webhook endpoint")
		}

		// The deliveries go with it through the foreign key's cascade: a queue for an
		// endpoint nobody will ever read is just work the delivery worker keeps retrying.
		rows, err := queries.DeleteWebhookEndpoint(ctx, id)
		if err != nil {
			return translate(err, "webhook endpoint")
		}
		if rows == 0 {
			return fmt.Errorf("%w: webhook endpoint", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "webhook.delete",
			EntityType: "webhook_endpoint",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"url": before.Url, "events": before.Events},
		})
		return nil
	})
}

// WebhookSecret decrypts one endpoint's signing secret, for the delivery worker.
func (s *Service) WebhookSecret(ctx context.Context, endpointID int64) ([]byte, error) {
	endpoint, err := s.q.GetWebhookEndpoint(ctx, endpointID)
	if err != nil {
		return nil, translate(err, "webhook endpoint")
	}

	secret, err := s.cipher.Decrypt(endpoint.SecretEnc, purposeWebhookSecret)
	if err != nil {
		return nil, fmt.Errorf("service: decrypt the webhook secret: %w", err)
	}
	return secret, nil
}

// userEvent is the part of a user an event carries.
//
// No credentials: not the UUID, not the passwords, not the subscription token. A webhook is
// delivered over somebody else's network to somebody else's server, and a receiver that needs
// a subscription link can ask the API for one with a token that can be revoked.
type userEvent struct {
	ID           int64
	Username     string
	XrayEmail    string
	Status       string
	TrafficUsed  int64
	TrafficLimit int64
	ExpiresAt    *time.Time
}

// userEventPayload renders one event body.
func userEventPayload(user userEvent, event string, at time.Time) []byte {
	body := map[string]any{
		"event": event,
		"at":    at.UTC().Format(time.RFC3339),
		"user": map[string]any{
			"id":            user.ID,
			"username":      user.Username,
			"xray_email":    user.XrayEmail,
			"status":        user.Status,
			"traffic_used":  user.TrafficUsed,
			"traffic_limit": user.TrafficLimit,
			"expires_at":    optionalTime(user.ExpiresAt),
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		// Only reachable if the map above grows a type json cannot encode, which the
		// compiler cannot catch. An empty payload is still delivered and still visible.
		return []byte(`{"event":"` + event + `","error":"payload could not be encoded"}`)
	}
	return encoded
}

// enqueueWebhook queues an event for every endpoint that subscribes to it.
//
// Called inside the caller's transaction, and its failure fails that transaction. Logging
// and carrying on is not an option here even in principle: in Postgres a failed statement
// aborts the transaction it ran in, and the commit that followed would roll back the change
// anyway. So the guarantee is the strong one — the change and its notification commit
// together or not at all. For enforcement that means a user whose event could not be queued
// is not switched off in this pass and is picked up by the next one; for creation, that the
// request fails and can be retried. Both beat a change nobody was told about.
func (s *Service) enqueueWebhook(ctx context.Context, queries *dbgen.Queries, event string, payload []byte) error {
	if !slices.Contains(KnownWebhookEvents, event) {
		// A programming error rather than a runtime one, and cheap to catch here: an event
		// no endpoint can subscribe to would be queued for nobody and look like it worked.
		return fmt.Errorf("service: %q is not a known webhook event", event)
	}

	_, err := queries.EnqueueWebhookDelivery(ctx, dbgen.EnqueueWebhookDeliveryParams{
		Event:   event,
		Payload: payload,
		Now:     s.now(),
	})
	if err != nil {
		s.log.ErrorContext(ctx, "could not queue a webhook delivery",
			slog.String("event", event), slog.Any("error", err))
		return translate(err, "webhook delivery")
	}
	return nil
}

// userEventOf is the event view of a stored user.
func userEventOf(user *dbgen.User) userEvent {
	return userEvent{
		ID:           user.ID,
		Username:     user.Username,
		XrayEmail:    user.XrayEmail,
		Status:       string(user.Status),
		TrafficUsed:  user.TrafficUsed,
		TrafficLimit: user.TrafficLimit,
		ExpiresAt:    user.ExpiresAt,
	}
}

func webhookEndpointOf(row dbgen.WebhookEndpoint) *WebhookEndpoint {
	return &WebhookEndpoint{
		ID:        row.ID,
		URL:       row.Url,
		Events:    row.Events,
		Enabled:   row.IsEnabled,
		CreatedAt: row.CreatedAt.UTC(),
	}
}

// validateWebhookURL rejects what cannot be delivered to.
func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return validationErrorf("webhook url is not a url: %v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		// http is allowed because a receiver on the same host or inside the same compose
		// network is a normal deployment; the signature is what authenticates the delivery,
		// not the transport.
		return validationErrorf("webhook url must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return validationErrorf("webhook url must have a host")
	}
	return nil
}

// validateWebhookEvents rejects subscriptions to events that do not exist.
//
// A typo in an event name would otherwise be a receiver that is simply never called, and the
// operator would look for the fault in their own code.
func validateWebhookEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, validationErrorf("a webhook endpoint must subscribe to at least one event, one of %s",
			strings.Join(KnownWebhookEvents, ", "))
	}

	seen := make(map[string]struct{}, len(events))
	out := make([]string, 0, len(events))
	for _, event := range events {
		event = strings.TrimSpace(event)
		if !slices.Contains(KnownWebhookEvents, event) {
			return nil, validationErrorf("unknown event %q; known events are %s",
				event, strings.Join(KnownWebhookEvents, ", "))
		}
		if _, dup := seen[event]; dup {
			continue
		}
		seen[event] = struct{}{}
		out = append(out, event)
	}
	return out, nil
}
