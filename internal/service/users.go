package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xraypanel/panel/internal/audit"
	"github.com/xraypanel/panel/internal/crypto"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// usernameMaxLength keeps a username short enough to display and long enough to be
// meaningful. It is enforced here rather than in the schema so the error is a 422 with
// an explanation instead of a constraint violation.
const usernameMaxLength = 64

// ssKeyBytes is the per-user Shadowsocks-2022 key length. The 128-bit methods want 16
// bytes; the 256-bit ones want 32. Sixteen is generated because a longer key is
// accepted for the shorter method but not the reverse, and the method is chosen per
// inbound, after the user already exists.
const ssKeyBytes = 16

// CreateUserInput describes a new subscriber.
type CreateUserInput struct {
	Username      string
	TrafficLimit  int64
	ResetStrategy string
	ExpiresAt     *time.Time
	Note          string
	TelegramID    *int64

	// GroupIDs is the access the user gets. Empty means the default groups, which is
	// what makes a bare "create this user" request produce someone who can connect.
	GroupIDs []int64
}

// CreateUser adds a subscriber and grants their access.
func (s *Service) CreateUser(ctx context.Context, actor audit.Actor, in CreateUserInput) (*dbgen.User, error) {
	username := strings.TrimSpace(in.Username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if in.TrafficLimit < 0 {
		return nil, validationErrorf("traffic limit must not be negative")
	}

	strategy, err := parseResetStrategy(in.ResetStrategy)
	if err != nil {
		return nil, err
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
		return nil, validationErrorf("expires_at must be in the future")
	}

	credentials, err := s.newUserCredentials()
	if err != nil {
		return nil, err
	}

	var created dbgen.User
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		user, err := queries.CreateUser(ctx, dbgen.CreateUserParams{
			Username:       username,
			XrayEmail:      credentials.statsKey,
			VlessUuid:      credentials.vlessUUID,
			TrojanPassword: credentials.trojanPassword,
			SsPassword:     credentials.ssPassword,
			ShortUuid:      credentials.subscriptionToken,
			Status:         dbgen.UserStatusActive,
			TrafficLimit:   in.TrafficLimit,
			ResetStrategy:  strategy,
			ExpiresAt:      in.ExpiresAt,
			Note:           in.Note,
			TelegramID:     in.TelegramID,
		})
		if err != nil {
			return translate(err, "user "+username)
		}

		groupIDs := in.GroupIDs
		if len(groupIDs) == 0 {
			groupIDs, err = defaultGroupIDs(ctx, queries)
			if err != nil {
				return err
			}
		}
		if err := assignGroups(ctx, queries, user.ID, groupIDs); err != nil {
			return err
		}

		s.bumpNodesForUser(ctx, queries, user.ID)

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.create",
			EntityType: "user",
			EntityID:   fmt.Sprint(user.ID),
			After:      audit.Redact(userFields(&user)),
		})

		if err := s.enqueueWebhook(ctx, queries, EventUserCreated,
			userEventPayload(userEventOf(&user), EventUserCreated, s.now())); err != nil {
			return err
		}

		created = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateUserInput carries only the fields a caller means to change.
//
// Every field is a pointer so that "not mentioned" and "set to zero" are different
// requests. Without that, omitting a traffic limit would silently mean unlimited.
type UpdateUserInput struct {
	Username      *string
	Status        *string
	TrafficLimit  *int64
	ResetStrategy *string
	Note          *string
	TelegramID    *int64

	// ExpiresAt is handled separately from the pointer above: SetExpiry distinguishes
	// "leave it alone" from "clear it", which one pointer cannot express.
	SetExpiry bool
	ExpiresAt *time.Time
}

// UpdateUser changes a subscriber.
func (s *Service) UpdateUser(ctx context.Context, actor audit.Actor, id int64, in UpdateUserInput) (*dbgen.User, error) {
	params := dbgen.UpdateUserParams{ID: id}

	if in.Username != nil {
		username := strings.TrimSpace(*in.Username)
		if err := validateUsername(username); err != nil {
			return nil, err
		}
		params.Username = &username
	}
	if in.Status != nil {
		status, err := parseUserStatus(*in.Status)
		if err != nil {
			return nil, err
		}
		params.Status = &status
	}
	if in.TrafficLimit != nil {
		if *in.TrafficLimit < 0 {
			return nil, validationErrorf("traffic limit must not be negative")
		}
		params.TrafficLimit = in.TrafficLimit
	}
	if in.ResetStrategy != nil {
		strategy, err := parseResetStrategy(*in.ResetStrategy)
		if err != nil {
			return nil, err
		}
		params.ResetStrategy = &strategy
	}
	params.Note = in.Note
	params.TelegramID = in.TelegramID

	var updated dbgen.User
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetUser(ctx, id)
		if err != nil {
			return translate(err, "user")
		}

		user, err := queries.UpdateUser(ctx, params)
		if err != nil {
			return translate(err, "user")
		}

		if in.SetExpiry {
			if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
				return validationErrorf("expires_at must be in the future")
			}
			user, err = queries.SetUserExpiry(ctx, dbgen.SetUserExpiryParams{
				ID:        id,
				ExpiresAt: in.ExpiresAt,
			})
			if err != nil {
				return translate(err, "user expiry")
			}
		}

		// A rename does not touch any node: the stats key is immutable and the
		// credentials are unchanged (ADR-007). Access changes do, so the version is
		// bumped only when something a node cares about moved.
		if statusChanged(before.Status, user.Status) {
			s.bumpNodesForUser(ctx, queries, id)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.update",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			Before:     audit.Redact(userFields(&before)),
			After:      audit.Redact(userFields(&user)),
		})

		updated = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// SetUserGroups replaces a user's access.
func (s *Service) SetUserGroups(ctx context.Context, actor audit.Actor, id int64, groupIDs []int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		if _, err := queries.GetUser(ctx, id); err != nil {
			return translate(err, "user")
		}

		before, err := queries.ListUserGroups(ctx, id)
		if err != nil {
			return translate(err, "user groups")
		}

		// Bump before and after the change: a group the user is leaving belongs to
		// nodes that must forget them, and those nodes are no longer reachable through
		// the user after the rows are gone.
		s.bumpNodesForUser(ctx, queries, id)

		if _, err := queries.ClearUserGroups(ctx, id); err != nil {
			return translate(err, "user groups")
		}
		if err := assignGroups(ctx, queries, id, groupIDs); err != nil {
			return err
		}

		s.bumpNodesForUser(ctx, queries, id)

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.set_groups",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"groups": groupNames(before)},
			After:      map[string]any{"group_ids": groupIDs},
		})
		return nil
	})
}

// RotateUserCredentials issues new secrets and invalidates the old subscription link.
//
// This is what an operator does when a link leaks. Every node has to be told, because
// the old uuid and passwords keep working on a node that has not been updated.
func (s *Service) RotateUserCredentials(ctx context.Context, actor audit.Actor, id int64) (*dbgen.User, error) {
	credentials, err := s.newUserCredentials()
	if err != nil {
		return nil, err
	}

	rotatedAt := s.now()

	var rotated dbgen.User
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		user, err := queries.RotateUserCredentials(ctx, dbgen.RotateUserCredentialsParams{
			ID:             id,
			VlessUuid:      credentials.vlessUUID,
			TrojanPassword: credentials.trojanPassword,
			SsPassword:     credentials.ssPassword,
			ShortUuid:      credentials.subscriptionToken,
			RevokedAt:      &rotatedAt,
		})
		if err != nil {
			return translate(err, "user")
		}

		s.bumpNodesForUser(ctx, queries, id)

		// The new values are deliberately not recorded. That they changed is the
		// audit-worthy fact; the values add nothing an auditor needs and something an
		// attacker wants.
		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.rotate_credentials",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			After:      map[string]any{"rotated_at": rotatedAt.UTC()},
		})

		rotated = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &rotated, nil
}

// ResetUserTraffic zeroes the enforcement counter and reactivates a limited account.
func (s *Service) ResetUserTraffic(ctx context.Context, actor audit.Actor, id int64) (*dbgen.User, error) {
	resetAt := s.now()

	var reset dbgen.User

	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetUser(ctx, id)
		if err != nil {
			return translate(err, "user")
		}

		user, err := queries.ResetUserTraffic(ctx, dbgen.ResetUserTrafficParams{
			ID:      id,
			ResetAt: &resetAt,
		})
		if err != nil {
			return translate(err, "user")
		}

		// A reset that lifts a limit changes what the node should allow.
		if before.Status == dbgen.UserStatusLimited {
			s.bumpNodesForUser(ctx, queries, id)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.reset_traffic",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"traffic_used": before.TrafficUsed, "status": before.Status},
			After:      map[string]any{"traffic_used": user.TrafficUsed, "status": user.Status},
		})

		reset = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &reset, nil
}

// RenewUser extends a subscription.
//
// The extension is added to the current expiry, or to now if the subscription already
// lapsed. Adding to a past expiry would hand back less time than was paid for, which is
// the kind of arithmetic mistake a customer notices before the operator does.
func (s *Service) RenewUser(ctx context.Context, actor audit.Actor, id int64, in RenewUserInput) (*dbgen.User, error) {
	extendBy, err := time.ParseDuration(in.ExtendBy)
	if err != nil {
		return nil, validationErrorf("extend_by must be a duration such as 720h, got %q", in.ExtendBy)
	}
	if extendBy <= 0 {
		return nil, validationErrorf("extend_by must be positive")
	}
	if in.TrafficLimit != nil && *in.TrafficLimit < 0 {
		return nil, validationErrorf("traffic limit must not be negative")
	}

	now := s.now()

	var renewed dbgen.User
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetUser(ctx, id)
		if err != nil {
			return translate(err, "user")
		}

		base := now
		if before.ExpiresAt != nil && before.ExpiresAt.After(now) {
			base = *before.ExpiresAt
		}
		expiry := base.Add(extendBy)

		user, err := queries.SetUserExpiry(ctx, dbgen.SetUserExpiryParams{
			ID:        id,
			ExpiresAt: &expiry,
		})
		if err != nil {
			return translate(err, "user expiry")
		}

		if in.TrafficLimit != nil {
			user, err = queries.UpdateUser(ctx, dbgen.UpdateUserParams{
				ID:           id,
				TrafficLimit: in.TrafficLimit,
			})
			if err != nil {
				return translate(err, "user")
			}
		}

		if in.ResetTraffic {
			resetAt := now
			user, err = queries.ResetUserTraffic(ctx, dbgen.ResetUserTrafficParams{
				ID:      id,
				ResetAt: &resetAt,
			})
			if err != nil {
				return translate(err, "user traffic")
			}
		}

		// A renewal is pointless if the account stays switched off, so an expired or
		// limited one comes back. A deliberately disabled account is left alone: that
		// was an operator decision, not a billing state.
		if user.Status == dbgen.UserStatusExpired || user.Status == dbgen.UserStatusLimited {
			user, err = queries.SetUserStatus(ctx, dbgen.SetUserStatusParams{
				ID:     id,
				Status: dbgen.UserStatusActive,
			})
			if err != nil {
				return translate(err, "user status")
			}
		}

		s.bumpNodesForUser(ctx, queries, id)

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.renew",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			Before: map[string]any{
				"expires_at": optionalTime(before.ExpiresAt),
				"status":     string(before.Status),
			},
			After: map[string]any{
				"expires_at":    optionalTime(user.ExpiresAt),
				"status":        string(user.Status),
				"extended_by":   in.ExtendBy,
				"traffic_reset": in.ResetTraffic,
			},
		})

		if err := s.enqueueWebhook(ctx, queries, EventUserRenewed,
			userEventPayload(userEventOf(&user), EventUserRenewed, now)); err != nil {
			return err
		}

		renewed = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &renewed, nil
}

func optionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// SetUsersStatus changes the status of several users at once.
func (s *Service) SetUsersStatus(ctx context.Context, actor audit.Actor, ids []int64, status string) (int64, error) {
	if len(ids) == 0 {
		return 0, validationErrorf("no user ids given")
	}
	parsed, err := parseUserStatus(status)
	if err != nil {
		return 0, err
	}

	var affected int64
	err = s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		count, err := queries.SetUserStatusBulk(ctx, dbgen.SetUserStatusBulkParams{
			Status: parsed,
			Ids:    ids,
		})
		if err != nil {
			return translate(err, "users")
		}

		// One bump per user rather than one for everything: the set of affected nodes
		// differs per user, and bumping every node would restart work on nodes that
		// were not touched.
		for _, id := range ids {
			s.bumpNodesForUser(ctx, queries, id)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.bulk_status",
			EntityType: "user",
			After:      map[string]any{"ids": ids, "status": status, "affected": count},
		})

		affected = count
		return nil
	})
	return affected, err
}

// DeleteUser removes a subscriber and their traffic history.
func (s *Service) DeleteUser(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetUser(ctx, id)
		if err != nil {
			return translate(err, "user")
		}

		// Bump first: after the rows are gone the query cannot find which nodes served
		// this user.
		s.bumpNodesForUser(ctx, queries, id)

		// traffic_records carries no foreign key to users, because the table is
		// partitioned and a cascade would touch every partition. The rows are removed
		// explicitly instead.
		if _, err := queries.DeleteUserTraffic(ctx, id); err != nil {
			return translate(err, "user traffic")
		}

		rows, err := queries.DeleteUser(ctx, id)
		if err != nil {
			return translate(err, "user")
		}
		if rows == 0 {
			return fmt.Errorf("%w: user", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "user.delete",
			EntityType: "user",
			EntityID:   fmt.Sprint(id),
			Before:     audit.Redact(userFields(&before)),
		})
		return nil
	})
}

// GetUser reads one subscriber.
func (s *Service) GetUser(ctx context.Context, id int64) (*dbgen.User, error) {
	user, err := s.q.GetUser(ctx, id)
	if err != nil {
		return nil, translate(err, "user")
	}
	return &user, nil
}

// --- helpers ---

type userCredentials struct {
	statsKey          string
	subscriptionToken string
	vlessUUID         pgtype.UUID
	trojanPassword    string
	ssPassword        string
}

func (s *Service) newUserCredentials() (*userCredentials, error) {
	statsKey, err := crypto.NewStatsKey()
	if err != nil {
		return nil, fmt.Errorf("service: generate stats key: %w", err)
	}
	token, err := crypto.NewSubscriptionToken()
	if err != nil {
		return nil, fmt.Errorf("service: generate subscription token: %w", err)
	}
	trojanPassword, err := crypto.RandomToken(24)
	if err != nil {
		return nil, fmt.Errorf("service: generate trojan password: %w", err)
	}
	ssKey, err := crypto.RandomBytes(ssKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("service: generate shadowsocks key: %w", err)
	}

	generated := uuid.New()

	return &userCredentials{
		statsKey:          statsKey,
		subscriptionToken: token,
		vlessUUID:         pgtype.UUID{Bytes: generated, Valid: true},
		trojanPassword:    trojanPassword,
		// Shadowsocks-2022 keys are base64 with padding, which is what both the config
		// and the ss:// link expect.
		ssPassword: base64.StdEncoding.EncodeToString(ssKey),
	}, nil
}

func validateUsername(username string) error {
	switch {
	case username == "":
		return validationErrorf("username must not be empty")
	case len(username) > usernameMaxLength:
		return validationErrorf("username must be at most %d characters", usernameMaxLength)
	case strings.ContainsAny(username, " \t\n\r/?#@:"):
		// These characters would have to be escaped wherever a username appears, and a
		// username is shown in remarks and used in filters.
		return validationErrorf("username must not contain whitespace or any of / ? # @ :")
	}
	return nil
}

func parseUserStatus(value string) (dbgen.UserStatus, error) {
	switch dbgen.UserStatus(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.UserStatusActive:
		return dbgen.UserStatusActive, nil
	case dbgen.UserStatusLimited:
		return dbgen.UserStatusLimited, nil
	case dbgen.UserStatusExpired:
		return dbgen.UserStatusExpired, nil
	case dbgen.UserStatusDisabled:
		return dbgen.UserStatusDisabled, nil
	default:
		return "", validationErrorf("status must be one of active, limited, expired, disabled")
	}
}

func parseResetStrategy(value string) (dbgen.ResetStrategy, error) {
	if strings.TrimSpace(value) == "" {
		return dbgen.ResetStrategyNever, nil
	}
	switch dbgen.ResetStrategy(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.ResetStrategyNever:
		return dbgen.ResetStrategyNever, nil
	case dbgen.ResetStrategyDaily:
		return dbgen.ResetStrategyDaily, nil
	case dbgen.ResetStrategyWeekly:
		return dbgen.ResetStrategyWeekly, nil
	case dbgen.ResetStrategyMonthly:
		return dbgen.ResetStrategyMonthly, nil
	default:
		return "", validationErrorf("reset_strategy must be one of never, daily, weekly, monthly")
	}
}

// statusChanged reports whether a status transition affects what nodes should allow.
func statusChanged(before, after dbgen.UserStatus) bool { return before != after }

func defaultGroupIDs(ctx context.Context, queries *dbgen.Queries) ([]int64, error) {
	groups, err := queries.ListDefaultInboundGroups(ctx)
	if err != nil {
		return nil, translate(err, "default groups")
	}
	ids := make([]int64, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	return ids, nil
}

// assignGroups grants access, rejecting a group that does not exist.
//
// The foreign key would catch it anyway, but as a constraint violation naming a
// constraint. Checking here means the caller is told which id was wrong.
func assignGroups(ctx context.Context, queries *dbgen.Queries, userID int64, groupIDs []int64) error {
	for _, groupID := range groupIDs {
		if _, err := queries.GetInboundGroup(ctx, groupID); err != nil {
			return translate(err, fmt.Sprintf("group %d", groupID))
		}
		if err := queries.AddUserToGroup(ctx, dbgen.AddUserToGroupParams{
			UserID:  userID,
			GroupID: groupID,
		}); err != nil {
			return translate(err, "group membership")
		}
	}
	return nil
}

func groupNames(groups []dbgen.InboundGroup) []string {
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

// userFields is the audit view of a user.
func userFields(user *dbgen.User) map[string]any {
	fields := map[string]any{
		"username":       user.Username,
		"status":         string(user.Status),
		"traffic_limit":  user.TrafficLimit,
		"traffic_used":   user.TrafficUsed,
		"reset_strategy": string(user.ResetStrategy),
		"note":           user.Note,
		// Named so audit.Redact replaces them: they are credentials, and the trail is
		// read by more people than the database is.
		"trojan_password": user.TrojanPassword,
		"ss_password":     user.SsPassword,
		"short_uuid":      user.ShortUuid,
	}
	if user.ExpiresAt != nil {
		fields["expires_at"] = user.ExpiresAt.UTC()
	}
	if user.TelegramID != nil {
		fields["telegram_id"] = *user.TelegramID
	}
	return fields
}
