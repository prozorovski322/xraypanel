package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/xraypanel/panel/internal/crypto"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// Idempotency scopes. A key is namespaced by the operation it belongs to, so the same
// key reused for a different operation is a mismatch rather than a coincidence.
const (
	ScopeUserCreate = "user.create"
	ScopeUserRenew  = "user.renew"
)

// StoredResponse is a completed operation's result, replayed for a retry.
type StoredResponse struct {
	StatusCode int
	Body       []byte
}

// Idempotent runs an operation at most once per key.
//
// The flow is claim, execute, complete. Claiming inserts the key in a single statement
// and reports whether this caller inserted it, so two concurrent retries have a decided
// outcome instead of a race: exactly one executes.
//
// A key seen before with a different request body is rejected rather than replayed. A
// client that reuses a key with different content has a bug, and answering with the old
// result would hide it while quietly not performing the new request.
//
// This matters because the clients that retry are exactly the ones this is for: a payment
// provider's webhook, a bot, a script behind a flaky connection.
func (s *Service) Idempotent(
	ctx context.Context,
	key, scope string,
	requestBody []byte,
	operation func(ctx context.Context) (StoredResponse, error),
) (StoredResponse, error) {
	if key == "" {
		// No key means no replay protection, which is the caller's choice.
		return operation(ctx)
	}

	requestHash := sha256.Sum256(requestBody)

	claimed, err := s.claimKey(ctx, key, scope, requestHash[:])
	if err != nil {
		return StoredResponse{}, err
	}

	if !claimed {
		return s.replay(ctx, key, scope, requestHash[:])
	}

	response, err := operation(ctx)
	if err != nil {
		// Release the claim so a retry may try again. Leaving it would tell the next
		// attempt that the operation already happened, when in fact it failed.
		if _, releaseErr := s.q.ReleaseIdempotencyKey(ctx, key); releaseErr != nil {
			s.log.WarnContext(ctx, "could not release a failed idempotency claim",
				"key", key, "error", releaseErr)
		}
		return StoredResponse{}, err
	}

	statusCode := int32(response.StatusCode)
	if err := s.q.CompleteIdempotencyKey(ctx, dbgen.CompleteIdempotencyKeyParams{
		Key:         key,
		Response:    response.Body,
		StatusCode:  &statusCode,
		CompletedAt: ptr(s.now()),
	}); err != nil {
		// The operation succeeded; failing the request now would make the caller retry
		// something already done. The cost is that this particular retry is not
		// recognised, which is the lesser problem.
		s.log.WarnContext(ctx, "could not record an idempotent result",
			"key", key, "error", err)
	}

	return response, nil
}

func (s *Service) claimKey(ctx context.Context, key, scope string, requestHash []byte) (bool, error) {
	_, err := s.q.ClaimIdempotencyKey(ctx, dbgen.ClaimIdempotencyKeyParams{
		Key:         key,
		Scope:       scope,
		RequestHash: requestHash,
		CreatedAt:   s.now(),
	})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING returns no rows, which is how a key that already exists
		// reports itself.
		return false, nil
	}
	return false, translate(err, "idempotency key")
}

// replay answers a retry from the stored result.
func (s *Service) replay(ctx context.Context, key, scope string, requestHash []byte) (StoredResponse, error) {
	stored, err := s.q.GetIdempotencyKey(ctx, key)
	if err != nil {
		return StoredResponse{}, translate(err, "idempotency key")
	}

	if stored.Scope != scope {
		return StoredResponse{}, fmt.Errorf("%w: that key belongs to %s", ErrIdempotencyMismatch, stored.Scope)
	}
	if !crypto.EqualHash(stored.RequestHash, requestHash) {
		return StoredResponse{}, ErrIdempotencyMismatch
	}

	if stored.CompletedAt == nil {
		// Another attempt holds the claim and has not finished. Reporting this as
		// in-flight lets the caller retry shortly, which is honest; inventing a result
		// would be a guess about an operation still running.
		return StoredResponse{}, ErrIdempotencyInFlight
	}

	response := StoredResponse{Body: stored.Response}
	if stored.StatusCode != nil {
		response.StatusCode = int(*stored.StatusCode)
	}
	return response, nil
}

// RenewUserInput extends a subscription.
type RenewUserInput struct {
	// ExtendBy is added to the current expiry, or to now if the subscription already
	// lapsed. Adding to a past expiry would give a shorter renewal than paid for.
	ExtendBy string

	// ResetTraffic zeroes the usage counter as part of the renewal, which is what a new
	// billing period usually means.
	ResetTraffic bool

	// TrafficLimit optionally changes the quota, for a renewal onto a different plan.
	TrafficLimit *int64
}

// ptr returns a pointer to a value, for the generated params that take one.
func ptr[T any](v T) *T { return &v }

// marshalResponse encodes a value for storage against an idempotency key.
func marshalResponse(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("service: encode idempotent response: %w", err)
	}
	return encoded, nil
}
