// Package xrayapi talks to a running Xray core's management API.
//
// It exists so that the common changes — a user added, a user removed, an inbound
// detached — do not restart the core. A restart drops every live connection on the
// node, which for a user watching a video is indistinguishable from the service being
// broken; and on a busy node those changes happen many times an hour.
//
// The API is reachable on loopback only, by the agent that owns the process. That is
// deliberate and it is why this client does not authenticate: anything that can reach
// the port can already add users and read every counter, so the protection is the
// listener's address, not a credential (see the api inbound in internal/xray/config).
package xrayapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	command "github.com/xraypanel/panel/internal/xray/app/proxyman/command"
	statscommand "github.com/xraypanel/panel/internal/xray/app/stats/command"
	protocolpb "github.com/xraypanel/panel/internal/xray/common/protocol"
	serial "github.com/xraypanel/panel/internal/xray/common/serial"
	ss2022 "github.com/xraypanel/panel/internal/xray/proxy/shadowsocks_2022"
	trojan "github.com/xraypanel/panel/internal/xray/proxy/trojan"
	vless "github.com/xraypanel/panel/internal/xray/proxy/vless"
)

// callTimeout bounds one API call. The core answers these from memory, so anything
// slower than this means it is wedged, and the reconciler needs to hear about that
// rather than block on it.
const callTimeout = 10 * time.Second

// Message type strings, as the core registers them. These are the one part of this
// package the compiler cannot check: a wrong string is accepted by the wire format and
// rejected by the core at runtime, which is why every one of them is exercised against
// a real core in the integration tests.
const (
	typeAddUser    = "xray.app.proxyman.command.AddUserOperation"
	typeRemoveUser = "xray.app.proxyman.command.RemoveUserOperation"

	typeVLESSAccount    = "xray.proxy.vless.Account"
	typeTrojanAccount   = "xray.proxy.trojan.Account"
	typeSS2022Account   = "xray.proxy.shadowsocks_2022.Account"
	vlessEncryptionNone = "none"
)

// Errors the reconciler has to tell apart from a real failure.
//
// The core reports both as ordinary errors with no status code, so they are recognised
// by their text. That is fragile in principle: an upstream rewording turns a benign
// answer into a failure. It is safe in practice because the consequence is bounded —
// the reconciler falls back to a restart, which always converges — and because the
// integration tests provoke both cases against the real binary, so a rewording breaks
// the build rather than a node.
var (
	// ErrAlreadyExists means a user with that stats key is already on the inbound.
	ErrAlreadyExists = errors.New("xrayapi: the user already exists on this inbound")

	// ErrNotFound means the user or inbound is not there, which for a removal is the
	// state the caller wanted anyway.
	ErrNotFound = errors.New("xrayapi: no such user or inbound")
)

// Account is a protocol-specific credential.
type Account interface {
	// typed wraps the credential the way the core expects to receive it.
	typed() (*serial.TypedMessage, error)
}

// VLESS is a VLESS credential. Flow must match the inbound's flow.
type VLESS struct {
	UUID string
	Flow string
}

// Trojan is a Trojan credential.
type Trojan struct {
	Password string
}

// Shadowsocks2022 is a Shadowsocks-2022 per-user key.
type Shadowsocks2022 struct {
	Key string
}

func (a VLESS) typed() (*serial.TypedMessage, error) {
	return marshalTyped(typeVLESSAccount, &vless.Account{
		Id:         a.UUID,
		Flow:       a.Flow,
		Encryption: vlessEncryptionNone,
	})
}

func (a Trojan) typed() (*serial.TypedMessage, error) {
	return marshalTyped(typeTrojanAccount, &trojan.Account{Password: a.Password})
}

func (a Shadowsocks2022) typed() (*serial.TypedMessage, error) {
	return marshalTyped(typeSS2022Account, &ss2022.Account{Key: a.Key})
}

// User is one account to add to an inbound.
type User struct {
	// Email is the immutable stats key (users.xray_email), not an address.
	Email string

	Account Account
}

// Client is a connection to one core's API.
type Client struct {
	conn    *grpc.ClientConn
	handler command.HandlerServiceClient
	stats   statscommand.StatsServiceClient
}

// Dial connects to the core's API endpoint, which the agent reads out of the
// configuration it applied rather than assuming, because a config patch can move it.
//
// No connection is attempted here: gRPC connects lazily, and the first call reports a
// core that is not listening. That suits the caller, which is about to make one.
func Dial(endpoint string) (*Client, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, errors.New("xrayapi: no api endpoint")
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("xrayapi: connect to %s: %w", endpoint, err)
	}
	return &Client{
		conn:    conn,
		handler: command.NewHandlerServiceClient(conn),
		stats:   statscommand.NewStatsServiceClient(conn),
	}, nil
}

// UserCounterPattern selects every per-user traffic counter.
const UserCounterPattern = "user>>>"

// Counters reads the core's counters whose names start with pattern.
//
// reset is false everywhere in this project except the fallback strategy: a counter the
// core forgets as it is read is traffic that cannot be recovered if the agent dies before
// it has reported it (ADR-008).
func (c *Client) Counters(ctx context.Context, pattern string, reset bool) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	response, err := c.stats.QueryStats(ctx, &statscommand.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, fmt.Errorf("xrayapi: could not read counters matching %q: %w", pattern, err)
	}

	counters := make(map[string]int64, len(response.GetStat()))
	for _, stat := range response.GetStat() {
		counters[stat.GetName()] = stat.GetValue()
	}
	return counters, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// AddUser puts a user on a running inbound.
func (c *Client) AddUser(ctx context.Context, tag string, user User) error {
	if strings.TrimSpace(user.Email) == "" {
		// Without a stats key the core would accept the user and report its traffic
		// under an empty counter, which the billing pipeline cannot attribute.
		return errors.New("xrayapi: refusing to add a user with no stats key")
	}
	if user.Account == nil {
		return fmt.Errorf("xrayapi: user %q has no account", user.Email)
	}

	account, err := user.Account.typed()
	if err != nil {
		return err
	}

	operation, err := marshalTyped(typeAddUser, &command.AddUserOperation{
		User: &protocolpb.User{
			// Level 0 is where the generated policy enables the per-user traffic
			// counters. A user at any other level would not be billed.
			Level:   0,
			Email:   user.Email,
			Account: account,
		},
	})
	if err != nil {
		return err
	}

	return c.alter(ctx, tag, operation, fmt.Sprintf("add user %q to inbound %q", user.Email, tag))
}

// RemoveUser takes a user off a running inbound, which drops that user's connections
// and leaves everyone else's alone.
func (c *Client) RemoveUser(ctx context.Context, tag, email string) error {
	operation, err := marshalTyped(typeRemoveUser, &command.RemoveUserOperation{Email: email})
	if err != nil {
		return err
	}
	return c.alter(ctx, tag, operation, fmt.Sprintf("remove user %q from inbound %q", email, tag))
}

// RemoveInbound closes one inbound's listener. Connections on other inbounds are not
// affected, which is what makes detaching an inbound cheaper than a restart.
func (c *Client) RemoveInbound(ctx context.Context, tag string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := c.handler.RemoveInbound(ctx, &command.RemoveInboundRequest{Tag: tag})
	if err != nil {
		return classify(err, fmt.Sprintf("remove inbound %q", tag))
	}
	return nil
}

// Users lists the stats keys currently loaded on an inbound.
//
// This is what lets the agent compare its intentions with the core's actual state
// instead of trusting its own bookkeeping: after a crash, a rollback, or an operator
// poking at the core by hand, the cache can be wrong and this cannot.
func (c *Client) Users(ctx context.Context, tag string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	response, err := c.handler.GetInboundUsers(ctx, &command.GetInboundUserRequest{Tag: tag})
	if err != nil {
		return nil, classify(err, fmt.Sprintf("list users on inbound %q", tag))
	}

	emails := make([]string, 0, len(response.GetUsers()))
	for _, user := range response.GetUsers() {
		emails = append(emails, user.GetEmail())
	}
	return emails, nil
}

// alter sends one AlterInbound operation.
func (c *Client) alter(ctx context.Context, tag string, operation *serial.TypedMessage, what string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := c.handler.AlterInbound(ctx, &command.AlterInboundRequest{Tag: tag, Operation: operation})
	if err != nil {
		return classify(err, what)
	}
	return nil
}

// marshalTyped serialises a message into the envelope the core expects.
func marshalTyped(typeName string, message proto.Message) (*serial.TypedMessage, error) {
	value, err := proto.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("xrayapi: encode %s: %w", typeName, err)
	}
	return &serial.TypedMessage{Type: typeName, Value: value}, nil
}

// classify recognises the two answers that are not failures.
func classify(err error, what string) error {
	text := strings.ToLower(err.Error())

	switch {
	case strings.Contains(text, "already exists"):
		return fmt.Errorf("xrayapi: could not %s: %w", what, ErrAlreadyExists)
	case strings.Contains(text, "not found"),
		strings.Contains(text, "not enough information"),
		strings.Contains(text, "no such inbound"):
		return fmt.Errorf("xrayapi: could not %s: %w", what, ErrNotFound)
	}
	return fmt.Errorf("xrayapi: could not %s: %w", what, err)
}
