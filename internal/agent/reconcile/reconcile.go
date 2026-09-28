// Package reconcile decides how to get a running Xray core from the configuration it
// has to the configuration the panel wants.
//
// The decision is the whole point of the package, and it is deliberately separated from
// carrying it out: the planner is pure, takes two configurations and returns what to do,
// and is therefore testable without a core, a panel or a process. Everything that can go
// wrong in the plan — restarting when nothing needed it, not restarting when something
// did — is a failure an operator experiences as dropped connections or as a node quietly
// running the wrong thing, and neither is easy to see after the fact.
//
// The rule is simple and the reasons are not symmetric:
//
//   - users added, removed or re-keyed: done on the running core, no restart;
//   - an inbound removed: done on the running core, no restart;
//   - an inbound added, or changed in any way other than its users: restart;
//   - anything structural (routing, dns, outbounds, policy, the api inbound): restart.
//
// Adding an inbound is in the restart column only because of what the core's API asks
// for: AddInbound takes a fully built internal configuration, whose transport, TLS and
// Reality messages would have to be transcribed and kept in step with every core
// release. Removing one takes a tag. See ADR-065.
package reconcile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/xraypanel/panel/internal/agent/xrayapi"
)

// apiTag is the local API inbound, which belongs to the structural part of the
// configuration and is never reconciled.
const apiTag = "api"

// Protocol names as they appear in a generated configuration.
const (
	protocolVLESS       = "vless"
	protocolTrojan      = "trojan"
	protocolShadowsocks = "shadowsocks"
)

// State is what a configuration says about the inbounds a core should serve.
type State struct {
	// Inbounds is keyed by tag.
	Inbounds map[string]Inbound
}

// Inbound is one inbound's protocol and users.
type Inbound struct {
	Tag      string
	Protocol string

	// Users is keyed by stats key (users.xray_email).
	Users map[string]User
}

// User is one account as the configuration describes it.
type User struct {
	Email   string
	Account xrayapi.Account

	// Fingerprint is everything about the credential that the core would have to be
	// told again if it changed. Compared as a string rather than reaching into the
	// account types, so a new protocol cannot be added without deciding what counts as
	// a change to it.
	Fingerprint string
}

// Plan is what has to happen to the running core.
type Plan struct {
	// Restart means the plan cannot be carried out on the running core. It is always a
	// valid answer: a restart converges from any state, which is why every failure in
	// the runtime path falls back to it.
	Restart bool

	// Reason says why a restart is needed, and is reported to the panel and logged. An
	// operator seeing connections drop deserves to know which change did it.
	Reason string

	// RemoveInbounds are tags to close, in a stable order.
	RemoveInbounds []string

	// RemoveUsers are applied before AddUsers, so that a user whose credentials
	// changed is removed and re-added rather than colliding with itself.
	RemoveUsers []UserRef
	AddUsers    []UserOp
}

// UserRef identifies a user on an inbound.
type UserRef struct {
	Tag   string
	Email string
}

// UserOp is a user to add to an inbound.
type UserOp struct {
	Tag  string
	User xrayapi.User
}

// Empty reports whether the plan asks for nothing at all, which is the common case:
// most configuration versions the panel pushes differ in one user.
func (p Plan) Empty() bool {
	return !p.Restart && len(p.RemoveInbounds) == 0 && len(p.RemoveUsers) == 0 && len(p.AddUsers) == 0
}

// Operations counts the runtime calls the plan needs.
func (p Plan) Operations() int {
	return len(p.RemoveInbounds) + len(p.RemoveUsers) + len(p.AddUsers)
}

// Tags lists the inbounds the plan touches, in a stable order. Verify checks these and
// only these: an inbound nobody changed is not worth an API call on every apply.
func (p Plan) Tags() []string {
	seen := make(map[string]struct{}, p.Operations())
	for _, ref := range p.RemoveUsers {
		seen[ref.Tag] = struct{}{}
	}
	for _, op := range p.AddUsers {
		seen[op.Tag] = struct{}{}
	}
	for _, tag := range p.RemoveInbounds {
		seen[tag] = struct{}{}
	}

	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// Snapshot is one configuration as the agent knows it: the document plus the hashes the
// panel computed for it.
type Snapshot struct {
	JSON           []byte
	StructuralHash string
	InboundHashes  map[string]string
}

// Compute works out how to get from the configuration the core is running to the one the
// panel wants.
//
// A restart is returned whenever the two cannot be compared with confidence — no
// previous configuration, a missing hash, a protocol this agent does not understand. The
// bias is deliberate: an unnecessary restart costs connections once, while a wrongly
// skipped one leaves the node serving something nobody asked for until somebody notices.
func Compute(previous, next Snapshot) (Plan, error) {
	if len(next.JSON) == 0 {
		return Plan{}, fmt.Errorf("reconcile: the desired configuration is empty; " +
			"stopping the core is the caller's decision, not a plan")
	}
	if len(previous.JSON) == 0 {
		return Plan{Restart: true, Reason: "the node has no configuration running yet"}, nil
	}
	if previous.StructuralHash == "" || next.StructuralHash == "" {
		// A configuration from before the panel sent hashes, or one assembled by hand.
		// Nothing can be concluded from a missing hash, so nothing is.
		return Plan{Restart: true, Reason: "one of the configurations carries no structural hash"}, nil
	}
	if previous.StructuralHash != next.StructuralHash {
		return Plan{Restart: true, Reason: "the structural part of the configuration changed"}, nil
	}

	before, err := Parse(previous.JSON)
	if err != nil {
		return Plan{Restart: true, Reason: fmt.Sprintf("the running configuration cannot be read: %v", err)}, nil
	}
	after, err := Parse(next.JSON)
	if err != nil {
		// Unlike the one above, this is a configuration the panel just sent. It will be
		// written to disk and started, and a core that accepts it is the authority on
		// whether it is valid — but it cannot be reconciled without being understood.
		return Plan{Restart: true, Reason: fmt.Sprintf("the new configuration cannot be reconciled: %v", err)}, nil
	}

	var result Plan

	for _, tag := range sortedTags(after.Inbounds) {
		desired := after.Inbounds[tag]

		current, existed := before.Inbounds[tag]
		if !existed {
			return Plan{
				Restart: true,
				Reason:  fmt.Sprintf("inbound %q was added, which the core's API cannot do at runtime", tag),
			}, nil
		}

		// The hashes decide whether the inbound is the same one, because they are
		// computed by the panel over everything except the user list. Comparing the
		// documents here would duplicate that rule in a second place, and the two
		// would eventually disagree.
		previousHash, hadPrevious := previous.InboundHashes[tag]
		nextHash, hasNext := next.InboundHashes[tag]
		if !hadPrevious || !hasNext {
			return Plan{
				Restart: true,
				Reason:  fmt.Sprintf("inbound %q has no hash to compare", tag),
			}, nil
		}
		if previousHash != nextHash {
			return Plan{
				Restart: true,
				Reason:  fmt.Sprintf("inbound %q changed in a way that needs a new listener", tag),
			}, nil
		}
		if current.Protocol != desired.Protocol {
			// Should be unreachable: the protocol is part of the hash. Kept because the
			// consequence of being wrong here is users added with credentials of the
			// wrong shape, which authenticate nobody.
			return Plan{
				Restart: true,
				Reason:  fmt.Sprintf("inbound %q changed protocol", tag),
			}, nil
		}

		for _, email := range sortedUsers(desired.Users) {
			wanted := desired.Users[email]
			existing, present := current.Users[email]

			switch {
			case !present:
				result.AddUsers = append(result.AddUsers, UserOp{
					Tag:  tag,
					User: xrayapi.User{Email: wanted.Email, Account: wanted.Account},
				})
			case existing.Fingerprint != wanted.Fingerprint:
				// Re-keyed: the core has no operation for changing a credential in
				// place, so the user is removed and added back. That drops this user's
				// own connections, which is unavoidable — their old key stopped being
				// valid, which is the point of rotating it.
				result.RemoveUsers = append(result.RemoveUsers, UserRef{Tag: tag, Email: email})
				result.AddUsers = append(result.AddUsers, UserOp{
					Tag:  tag,
					User: xrayapi.User{Email: wanted.Email, Account: wanted.Account},
				})
			}
		}

		for _, email := range sortedUsers(current.Users) {
			if _, keep := desired.Users[email]; !keep {
				result.RemoveUsers = append(result.RemoveUsers, UserRef{Tag: tag, Email: email})
			}
		}
	}

	// Inbounds the panel no longer wants. Their users need no attention: closing the
	// listener takes their connections with it, and that is the intent.
	for _, tag := range sortedTags(before.Inbounds) {
		if _, keep := after.Inbounds[tag]; !keep {
			result.RemoveInbounds = append(result.RemoveInbounds, tag)
		}
	}

	return result, nil
}

// Parse reads the inbounds and their users out of a generated configuration.
//
// The configuration is the only description of desired users the node has, and that is
// on purpose: one document to apply, one document to reconcile against, no second
// channel that can disagree with it.
func Parse(configJSON []byte) (State, error) {
	var document struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Method  string `json:"method"`
				Clients []struct {
					Email    string `json:"email"`
					ID       string `json:"id"`
					Password string `json:"password"`
					Flow     string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configJSON, &document); err != nil {
		return State{}, fmt.Errorf("reconcile: read configuration: %w", err)
	}

	state := State{Inbounds: make(map[string]Inbound, len(document.Inbounds))}

	for _, raw := range document.Inbounds {
		if raw.Tag == apiTag {
			continue
		}
		if raw.Protocol != protocolVLESS && raw.Protocol != protocolTrojan && raw.Protocol != protocolShadowsocks {
			// A protocol this agent cannot build credentials for. Reported rather than
			// skipped: silently ignoring an inbound would mean reconciling around it and
			// leaving its users to whatever the core happened to have.
			return State{}, fmt.Errorf("reconcile: inbound %q has protocol %q, which this agent cannot reconcile",
				raw.Tag, raw.Protocol)
		}

		inbound := Inbound{
			Tag:      raw.Tag,
			Protocol: raw.Protocol,
			Users:    make(map[string]User, len(raw.Settings.Clients)),
		}

		for _, client := range raw.Settings.Clients {
			if strings.TrimSpace(client.Email) == "" {
				return State{}, fmt.Errorf("reconcile: inbound %q has a client with no stats key", raw.Tag)
			}

			user, err := buildUser(raw.Protocol, raw.Tag, client.Email, client.ID, client.Password, client.Flow)
			if err != nil {
				return State{}, err
			}
			inbound.Users[client.Email] = user
		}

		state.Inbounds[raw.Tag] = inbound
	}

	return state, nil
}

// buildUser turns one client entry into the credential the core's API expects.
func buildUser(protocol, tag, email, id, password, flow string) (User, error) {
	switch protocol {
	case protocolVLESS:
		if id == "" {
			return User{}, fmt.Errorf("reconcile: inbound %q: vless client %q has no id", tag, email)
		}
		return User{
			Email:   email,
			Account: xrayapi.VLESS{UUID: id, Flow: flow},
			// Flow is part of the fingerprint because Xray stores it per client: a
			// changed flow is a changed credential, and re-adding the user is how it
			// takes effect.
			Fingerprint: "vless:" + id + ":" + flow,
		}, nil

	case protocolTrojan:
		if password == "" {
			return User{}, fmt.Errorf("reconcile: inbound %q: trojan client %q has no password", tag, email)
		}
		return User{
			Email:       email,
			Account:     xrayapi.Trojan{Password: password},
			Fingerprint: "trojan:" + password,
		}, nil

	case protocolShadowsocks:
		if password == "" {
			return User{}, fmt.Errorf("reconcile: inbound %q: shadowsocks client %q has no key", tag, email)
		}
		return User{
			Email:       email,
			Account:     xrayapi.Shadowsocks2022{Key: password},
			Fingerprint: "ss2022:" + password,
		}, nil
	}

	return User{}, fmt.Errorf("reconcile: inbound %q: unsupported protocol %q", tag, protocol)
}

func sortedTags(inbounds map[string]Inbound) []string {
	tags := make([]string, 0, len(inbounds))
	for tag := range inbounds {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func sortedUsers(users map[string]User) []string {
	emails := make([]string, 0, len(users))
	for email := range users {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	return emails
}
