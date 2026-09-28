package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/xraypanel/panel/internal/audit"
	dbgen "github.com/xraypanel/panel/internal/postgres/gen"
)

// CreateGroupInput describes a new access group.
type CreateGroupInput struct {
	Name        string
	Description string
	IsDefault   bool
	InboundIDs  []int64
}

// CreateGroup adds an access group.
func (s *Service) CreateGroup(ctx context.Context, actor audit.Actor, in CreateGroupInput) (*dbgen.InboundGroup, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, validationErrorf("group needs a name")
	}

	var created dbgen.InboundGroup
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		group, err := queries.CreateInboundGroup(ctx, dbgen.CreateInboundGroupParams{
			Name:        name,
			Description: in.Description,
			IsDefault:   in.IsDefault,
		})
		if err != nil {
			return translate(err, "group "+name)
		}

		if err := setGroupInbounds(ctx, queries, group.ID, in.InboundIDs); err != nil {
			return err
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "group.create",
			EntityType: "group",
			EntityID:   fmt.Sprint(group.ID),
			After: map[string]any{
				"name": group.Name, "is_default": group.IsDefault, "inbound_ids": in.InboundIDs,
			},
		})

		created = group
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateGroupInput carries only the fields to change. A nil InboundIDs leaves membership
// alone; an empty non-nil slice clears it.
type UpdateGroupInput struct {
	Name        *string
	Description *string
	IsDefault   *bool

	SetInbounds bool
	InboundIDs  []int64
}

// UpdateGroup changes a group and optionally replaces its membership.
func (s *Service) UpdateGroup(ctx context.Context, actor audit.Actor, id int64, in UpdateGroupInput) (*dbgen.InboundGroup, error) {
	var updated dbgen.InboundGroup

	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetInboundGroup(ctx, id)
		if err != nil {
			return translate(err, "group")
		}

		group, err := queries.UpdateInboundGroup(ctx, dbgen.UpdateInboundGroupParams{
			ID:          id,
			Name:        in.Name,
			Description: in.Description,
			IsDefault:   in.IsDefault,
		})
		if err != nil {
			return translate(err, "group")
		}

		if in.SetInbounds {
			// Membership changes what every member's node should be configured with, so
			// versions are bumped for the users in this group, both before and after:
			// an inbound leaving the group belongs to nodes that must forget those users.
			if err := s.bumpNodesForGroupMembers(ctx, queries, id); err != nil {
				return err
			}
			if _, err := queries.ClearGroupInbounds(ctx, id); err != nil {
				return translate(err, "group membership")
			}
			if err := setGroupInbounds(ctx, queries, id, in.InboundIDs); err != nil {
				return err
			}
			if err := s.bumpNodesForGroupMembers(ctx, queries, id); err != nil {
				return err
			}
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "group.update",
			EntityType: "group",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"name": before.Name, "is_default": before.IsDefault},
			After:      map[string]any{"name": group.Name, "is_default": group.IsDefault},
		})

		updated = group
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteGroup removes a group. User membership cascades, which revokes access.
func (s *Service) DeleteGroup(ctx context.Context, actor audit.Actor, id int64) error {
	return s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		before, err := queries.GetInboundGroup(ctx, id)
		if err != nil {
			return translate(err, "group")
		}

		// Bump while the membership rows still exist: afterwards there is no way to find
		// which nodes served the users who were in this group.
		if err := s.bumpNodesForGroupMembers(ctx, queries, id); err != nil {
			return err
		}

		rows, err := queries.DeleteInboundGroup(ctx, id)
		if err != nil {
			return translate(err, "group")
		}
		if rows == 0 {
			return fmt.Errorf("%w: group", ErrNotFound)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "group.delete",
			EntityType: "group",
			EntityID:   fmt.Sprint(id),
			Before:     map[string]any{"name": before.Name},
		})
		return nil
	})
}

// AddUsersToGroup grants access to several users at once.
func (s *Service) AddUsersToGroup(ctx context.Context, actor audit.Actor, groupID int64, userIDs []int64) (int64, error) {
	if len(userIDs) == 0 {
		return 0, validationErrorf("no user ids given")
	}

	var added int64
	err := s.tx(ctx, func(queries *dbgen.Queries, recorder *audit.Recorder) error {
		if _, err := queries.GetInboundGroup(ctx, groupID); err != nil {
			return translate(err, "group")
		}

		count, err := queries.AddUsersToGroupBulk(ctx, dbgen.AddUsersToGroupBulkParams{
			UserIds: userIDs,
			GroupID: groupID,
		})
		if err != nil {
			return translate(err, "group membership")
		}

		for _, userID := range userIDs {
			s.bumpNodesForUser(ctx, queries, userID)
		}

		recorder.Record(ctx, actor, audit.Entry{
			Action:     "group.add_users",
			EntityType: "group",
			EntityID:   fmt.Sprint(groupID),
			After:      map[string]any{"user_ids": userIDs, "added": count},
		})

		added = count
		return nil
	})
	return added, err
}

// bumpNodesForGroupMembers marks every node serving any member of a group.
func (s *Service) bumpNodesForGroupMembers(ctx context.Context, queries *dbgen.Queries, groupID int64) error {
	userIDs, err := queries.ListGroupUserIDs(ctx, groupID)
	if err != nil {
		return translate(err, "group members")
	}
	for _, userID := range userIDs {
		s.bumpNodesForUser(ctx, queries, userID)
	}
	return nil
}

// setGroupInbounds adds membership, rejecting an inbound that does not exist.
//
// The foreign key would catch it as a constraint violation naming a constraint; checking
// here tells the caller which id was wrong.
func setGroupInbounds(ctx context.Context, queries *dbgen.Queries, groupID int64, inboundIDs []int64) error {
	for _, inboundID := range inboundIDs {
		if _, err := queries.GetInbound(ctx, inboundID); err != nil {
			return translate(err, fmt.Sprintf("inbound %d", inboundID))
		}
		if err := queries.AddInboundToGroup(ctx, dbgen.AddInboundToGroupParams{
			GroupID:   groupID,
			InboundID: inboundID,
		}); err != nil {
			return translate(err, "group membership")
		}
	}
	return nil
}
