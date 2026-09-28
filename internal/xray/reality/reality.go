// Package reality generates the key material a Reality inbound needs.
//
// Reality replaces a conventional TLS certificate with an X25519 key pair plus a
// set of short identifiers. The server keeps the private key; clients are given the
// public key and one short id, and both end up in the subscription link.
package reality

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Key material sizes and limits, fixed by the Reality protocol.
const (
	// keySize is the X25519 key length in bytes, for both halves.
	keySize = 32

	// shortIDMaxBytes is the widest short id Reality accepts. It is carried in the
	// handshake as a fixed eight byte field, so anything longer cannot be expressed.
	shortIDMaxBytes = 8

	// DefaultShortIDCount is how many ids a new key set gets. More than one so that
	// clients can be grouped or rotated without regenerating the key pair, few
	// enough that the list stays readable.
	DefaultShortIDCount = 4
)

// KeyPair is an X25519 key pair encoded the way Xray expects.
//
// Both halves use unpadded base64url, which is what `xray x25519` prints and what
// the privateKey field and the pbk link parameter are read as. Standard base64
// would round-trip through Go fine and be rejected by the client.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair creates a new X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("reality: generate x25519 key: %w", err)
	}

	return &KeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
	}, nil
}

// PublicKeyFor derives the public half from a stored private key.
//
// It exists so that a key pair whose public half was lost, or was never stored, can
// be recovered from the private key alone rather than being regenerated, which would
// invalidate every client link issued from it.
func PublicKeyFor(privateKey string) (string, error) {
	raw, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}

	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("reality: invalid private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

// ValidateKeyPair checks that a stored pair is well formed and that the public half
// really belongs to the private one.
//
// The mismatch case is worth checking explicitly: a config built from a private key
// with somebody else's public key produces an inbound that starts cleanly and
// rejects every client, with nothing in the logs to explain why.
func ValidateKeyPair(privateKey, publicKey string) error {
	derived, err := PublicKeyFor(privateKey)
	if err != nil {
		return err
	}
	if _, err := decodeKey(publicKey); err != nil {
		return fmt.Errorf("reality: public key: %w", err)
	}
	if derived != publicKey {
		return errors.New("reality: public key does not belong to the private key")
	}
	return nil
}

// decodeKey accepts any base64 variant and returns the 32 raw bytes.
//
// Xray prints unpadded base64url, but operators paste keys from all sorts of places,
// and a key that differs only in padding is the same key.
func decodeKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("reality: key is empty")
	}

	decoders := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, decoder := range decoders {
		if raw, err := decoder.DecodeString(encoded); err == nil && len(raw) == keySize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("reality: key must decode to %d bytes from base64", keySize)
}

// GenerateShortIDs creates count short identifiers.
//
// Every id is the full eight bytes. Reality matches a client's id against the list
// by exact value, and an empty id means "accept a client that sends none", so an
// empty entry would quietly turn the list into an optional check. It is never
// generated here.
func GenerateShortIDs(count int) ([]string, error) {
	if count < 1 || count > 64 {
		return nil, fmt.Errorf("reality: short id count %d out of range 1..64", count)
	}

	ids := make([]string, 0, count)
	seen := make(map[string]struct{}, count)

	for len(ids) < count {
		raw := make([]byte, shortIDMaxBytes)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, fmt.Errorf("reality: read random short id: %w", err)
		}
		id := hex.EncodeToString(raw)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

// ValidateShortID checks one short id.
func ValidateShortID(id string) error {
	if id == "" {
		// Allowed by Reality itself, refused here: see GenerateShortIDs.
		return errors.New("reality: short id must not be empty")
	}
	if len(id)%2 != 0 {
		return fmt.Errorf("reality: short id %q must have an even number of hex digits", id)
	}
	if len(id) > shortIDMaxBytes*2 {
		return fmt.Errorf("reality: short id %q is longer than %d bytes", id, shortIDMaxBytes)
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("reality: short id %q is not hexadecimal", id)
	}
	return nil
}

// ValidateShortIDs checks a whole list and rejects duplicates.
func ValidateShortIDs(ids []string) error {
	if len(ids) == 0 {
		return errors.New("reality: at least one short id is required")
	}

	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if err := ValidateShortID(id); err != nil {
			return err
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("reality: short id %q is listed twice", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// ValidateDest checks the handshake target.
//
// Reality forwards a probing client to this address, so it has to be a real
// host:port that speaks TLS. A bare hostname is rejected rather than defaulted to
// 443: a silently assumed port produces an inbound that works until the day someone
// points it at a host serving TLS elsewhere.
func ValidateDest(dest string) error {
	if strings.TrimSpace(dest) == "" {
		return errors.New("reality: dest is required")
	}

	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return fmt.Errorf("reality: dest %q must be host:port", dest)
	}
	if host == "" {
		return fmt.Errorf("reality: dest %q has no host", dest)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("reality: dest %q has an invalid port", dest)
	}
	return nil
}

// ValidateServerNames checks the SNI list a client may present.
func ValidateServerNames(names []string) error {
	if len(names) == 0 {
		return errors.New("reality: at least one server name is required")
	}
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return errors.New("reality: server name must not be empty")
		}
		if strings.ContainsAny(name, " \t/:") {
			return fmt.Errorf("reality: server name %q must be a bare hostname", name)
		}
	}
	return nil
}
