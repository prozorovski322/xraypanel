package reconcile

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraypanel/panel/internal/agent/xrayapi"
)

// Core is the part of the running core's API a plan needs. An interface because the
// interesting cases — a user that is already there, an inbound that is already gone, a
// call that fails halfway through a plan — are worth testing without a live process.
type Core interface {
	AddUser(ctx context.Context, tag string, user xrayapi.User) error
	RemoveUser(ctx context.Context, tag, email string) error
	RemoveInbound(ctx context.Context, tag string) error

	// Users lists the stats keys the core currently has on an inbound.
	Users(ctx context.Context, tag string) ([]string, error)
}

// Execute carries out a plan against a running core.
//
// Every step is written to converge rather than to be right the first time: a removal of
// something already absent and an addition of something already present are both
// treated as the state the plan wanted. The agent's picture of the core can be stale —
// after a crash, a rollback, or an operator using the API by hand — and the useful
// behaviour then is to end up in the desired state, not to report that the world moved.
//
// A step that fails for any other reason stops the plan and is returned. The caller
// falls back to a restart, which converges from any state.
func Execute(ctx context.Context, core Core, plan Plan) error {
	if plan.Restart {
		return errors.New("reconcile: this plan calls for a restart and cannot be executed at runtime")
	}

	// Removals first: a re-keyed user appears in both lists, and adding before removing
	// would collide with the credential being replaced.
	for _, ref := range plan.RemoveUsers {
		err := core.RemoveUser(ctx, ref.Tag, ref.Email)
		if err != nil && !errors.Is(err, xrayapi.ErrNotFound) {
			return fmt.Errorf("reconcile: %w", err)
		}
	}

	for _, op := range plan.AddUsers {
		err := core.AddUser(ctx, op.Tag, op.User)
		if errors.Is(err, xrayapi.ErrAlreadyExists) {
			// The core has this stats key already, with credentials the plan believes are
			// wrong. Replacing it is what the plan meant.
			if removeErr := core.RemoveUser(ctx, op.Tag, op.User.Email); removeErr != nil &&
				!errors.Is(removeErr, xrayapi.ErrNotFound) {
				return fmt.Errorf("reconcile: %w", removeErr)
			}
			err = core.AddUser(ctx, op.Tag, op.User)
		}
		if err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
	}

	// Last, because a failure here leaves users converged on the inbounds that stay,
	// and because the listener being closed is the most visible of the three.
	for _, tag := range plan.RemoveInbounds {
		err := core.RemoveInbound(ctx, tag)
		if err != nil && !errors.Is(err, xrayapi.ErrNotFound) {
			return fmt.Errorf("reconcile: %w", err)
		}
	}

	return nil
}

// Verify asks the core what it actually has and compares it with what was wanted.
//
// This is not defensive programming for its own sake. The messages this agent sends the
// core are a transcription of the core's own schema, made by hand (ADR-065), and the one
// mistake that transcription can make without anybody noticing is a message the core
// accepts and does not act on. An operation that reports success and changes nothing
// would otherwise show up as a user who cannot connect — reported by the user, days
// later, to somebody who has no reason to suspect the control plane.
//
// The cost is one in-memory call per inbound that was touched.
func Verify(ctx context.Context, core Core, desired State, tags []string) error {
	for _, tag := range tags {
		inbound, wanted := desired.Inbounds[tag]
		if !wanted {
			// Removed inbounds are not checked: the core answers for an inbound it no
			// longer has with an error that says exactly that, which proves nothing.
			continue
		}

		actual, err := core.Users(ctx, tag)
		if err != nil {
			return fmt.Errorf("reconcile: cannot confirm the users on inbound %q: %w", tag, err)
		}

		have := make(map[string]struct{}, len(actual))
		for _, email := range actual {
			have[email] = struct{}{}
		}

		for email := range inbound.Users {
			if _, present := have[email]; !present {
				return fmt.Errorf(
					"reconcile: the core accepted the changes to inbound %q but user %q is not there",
					tag, email)
			}
		}
		for email := range have {
			if _, wanted := inbound.Users[email]; !wanted {
				return fmt.Errorf(
					"reconcile: the core still has user %q on inbound %q after it was removed",
					email, tag)
			}
		}
	}
	return nil
}
