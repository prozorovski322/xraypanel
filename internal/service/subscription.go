package service

import (
	"context"
	"fmt"

	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
	"github.com/xraypanel/panel/internal/sublink"
)

// PublicSubscription is what the public endpoint serves for one token.
type PublicSubscription struct {
	User *dbgen.User

	// Status is the user's effective status: the stored one, corrected for a limit or an
	// expiry the enforcement worker has not got round to yet.
	Status dbgen.UserStatus

	// Subscription holds no endpoints unless Status is active.
	Subscription *sublink.Subscription

	ProfileTitle        string
	UpdateIntervalHours int
}

// Active reports whether the subscription carries working endpoints.
func (p *PublicSubscription) Active() bool { return p.Status == dbgen.UserStatusActive }

// SubscriptionByToken resolves the secret in a public /sub/{token} URL.
//
// A token that is malformed, unknown or has been rotated away is ErrNotFound, and the
// three are deliberately indistinguishable to the caller.
//
// A user who is not active still gets an answer, with no endpoints in it. Refusing
// outright would leave the client showing its previous, now useless, servers with no
// explanation; an empty profile with the quota header lets it show that the traffic ran
// out or the subscription lapsed, which is the explanation the user needs.
func (s *Service) SubscriptionByToken(ctx context.Context, token string) (*PublicSubscription, error) {
	// Shape first: a request that could not possibly match costs no database round trip,
	// which is most of what a scan for tokens consists of.
	if !plausibleSubscriptionToken(token) {
		return nil, fmt.Errorf("%w: subscription", ErrNotFound)
	}

	user, err := s.q.GetUserBySubscriptionToken(ctx, token)
	if err != nil {
		return nil, translate(err, "subscription")
	}

	result := &PublicSubscription{
		User:                &user,
		Status:              s.effectiveStatus(&user),
		ProfileTitle:        s.cfg.ProfileTitle,
		UpdateIntervalHours: s.cfg.SubscriptionUpdateHours,
	}

	if !result.Active() {
		// Only the quota summary: resolving endpoints nobody will be given would decrypt
		// key material for nothing.
		result.Subscription = &sublink.Subscription{
			UserInfo:       userInfoOf(&user),
			Title:          s.cfg.ProfileTitle,
			UpdateInterval: s.cfg.SubscriptionUpdateHours,
		}
		return result, nil
	}

	sub, err := s.BuildSubscription(ctx, &user)
	if err != nil {
		return nil, err
	}
	result.Subscription = sub
	return result, nil
}

// effectiveStatus corrects the stored status for limits the enforcement worker has not
// applied yet.
//
// The worker runs every thirty seconds, and in that window the stored status still says
// active. Handing out working links in it would be harmless, since the nodes drop the
// user moments later, but it would also be the one place that disagrees with what the
// page shows a moment afterwards.
func (s *Service) effectiveStatus(user *dbgen.User) dbgen.UserStatus {
	if user.Status != dbgen.UserStatusActive {
		return user.Status
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(s.now()) {
		return dbgen.UserStatusExpired
	}
	if user.TrafficLimit > 0 && user.TrafficUsed >= user.TrafficLimit {
		return dbgen.UserStatusLimited
	}
	return dbgen.UserStatusActive
}

// plausibleSubscriptionToken accepts anything the token generator could have produced,
// and a little more, so that a future change of length does not strand old tokens.
func plausibleSubscriptionToken(token string) bool {
	if len(token) < 16 || len(token) > 64 {
		return false
	}
	for i := range len(token) {
		c := token[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
