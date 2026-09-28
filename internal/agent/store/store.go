// Package store is the node agent's local state: its identity, and the last
// configuration it was told to run.
//
// It exists so that the panel being unreachable is not an outage. An agent that
// restarts while the panel is down brings Xray back up from here, with the users it
// had, and only then starts trying to reconnect. Without it, a panel outage would
// become a service outage on every node that happened to restart during it.
//
// BoltDB rather than plain files: the identity and the configuration have to move
// together, and a crash between writing two files leaves a node with a certificate
// for a configuration it does not have, or the reverse.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket and key names. Flat and few: this is a cache with two entries, not a database.
var (
	bucketMeta = []byte("meta")

	keyIdentity = []byte("identity")

	// keyConfig holds a configuration the core was seen running. keyPending holds one
	// that was being applied when the agent last stopped.
	//
	// Two keys rather than one, because an agent killed between writing a configuration
	// and confirming it must not come back believing it has nothing to run. That is the
	// one moment where the local cache is needed most: a node rebooting during a panel
	// outage. With a pending record it starts the configuration anyway and reports it as
	// unconfirmed, so the panel sends it again and confirms it.
	keyConfig  = []byte("config")
	keyPending = []byte("pending")
)

// openTimeout bounds how long Open waits for the file lock.
//
// A second agent on the same volume is a misconfiguration — two supervisors fighting
// over one Xray — and it should fail loudly and quickly rather than hang for ever.
const openTimeout = 5 * time.Second

// ErrNotEnrolled means the agent has no identity yet and has to enrol.
var ErrNotEnrolled = errors.New("store: this node has not been enrolled")

// Store is the agent's local state. Safe for concurrent use.
type Store struct {
	db *bolt.DB
}

// Identity is what the panel issued to this node at enrollment.
//
// The private key is held here in the clear. There is nothing to encrypt it with: any
// key the agent could use would have to live on the same volume, and a lock whose key
// is taped to it is theatre. What protects it is file permissions and the fact that
// the volume belongs to the node; a node whose disk is readable by an attacker has
// already lost, because the same disk holds every user's credentials.
type Identity struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`

	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
	CAPEM   []byte `json:"ca_pem"`

	// ServerName is the name to require in the panel's certificate.
	ServerName string `json:"server_name"`

	// NotAfter is when the certificate stops being accepted, so the agent can say so
	// in its log before it becomes an outage.
	NotAfter time.Time `json:"not_after"`

	EnrolledAt time.Time `json:"enrolled_at"`
}

// AppliedConfig is the configuration the agent last successfully applied.
type AppliedConfig struct {
	Version int64 `json:"version"`

	// JSON is the whole config.json. Empty means the panel asked for nothing to run,
	// which is what a node with no inbounds looks like.
	JSON []byte `json:"json"`

	StructuralHash string            `json:"structural_hash"`
	InboundHashes  map[string]string `json:"inbound_hashes"`
	AppliedAt      time.Time         `json:"applied_at"`
}

// Empty reports whether this configuration asks for nothing to be running.
func (c *AppliedConfig) Empty() bool { return c == nil || len(c.JSON) == 0 }

// Open opens or creates the store at path, creating the directory if needed.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}

	// 0600: the file holds this node's private key.
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketMeta)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: initialise %s: %w", path, err)
	}

	return &Store{db: db}, nil
}

// Close releases the file lock.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// Identity returns the stored identity, or ErrNotEnrolled when there is none.
func (s *Store) Identity() (*Identity, error) {
	var identity *Identity
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(keyIdentity)
		if raw == nil {
			return ErrNotEnrolled
		}
		identity = &Identity{}
		return json.Unmarshal(raw, identity)
	})
	if err != nil {
		if errors.Is(err, ErrNotEnrolled) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("store: read identity: %w", err)
	}
	return identity, nil
}

// SaveIdentity stores the identity, replacing any previous one.
//
// Replacing is what re-enrollment looks like from here, and the old certificate is of
// no further use: the panel stops recognising it the moment it issues a new one.
func (s *Store) SaveIdentity(identity *Identity) error {
	if identity == nil || identity.NodeID == 0 || len(identity.CertPEM) == 0 || len(identity.KeyPEM) == 0 {
		return errors.New("store: refusing to save an incomplete identity")
	}

	encoded, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("store: encode identity: %w", err)
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyIdentity, encoded)
	})
	if err != nil {
		return fmt.Errorf("store: write identity: %w", err)
	}
	return nil
}

// AppliedConfig returns the last confirmed configuration, or nil when there is none.
//
// nil and "a configuration that runs nothing" are different: the first means this
// agent has never been told anything, so it must wait for the panel rather than
// deciding for itself.
func (s *Store) AppliedConfig() (*AppliedConfig, error) {
	return s.readConfig(keyConfig)
}

// PendingConfig returns a configuration that was being applied and never confirmed.
func (s *Store) PendingConfig() (*AppliedConfig, error) {
	return s.readConfig(keyPending)
}

func (s *Store) readConfig(key []byte) (*AppliedConfig, error) {
	var config *AppliedConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(key)
		if raw == nil {
			return nil
		}
		config = &AppliedConfig{}
		return json.Unmarshal(raw, config)
	})
	if err != nil {
		return nil, fmt.Errorf("store: read config: %w", err)
	}
	return config, nil
}

// SavePendingConfig records a configuration the agent is about to apply.
//
// Written before Xray is touched, so that a crash mid-apply leaves evidence of what was
// being attempted rather than nothing at all.
func (s *Store) SavePendingConfig(config *AppliedConfig) error {
	if config == nil {
		return errors.New("store: refusing to save a nil configuration")
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("store: encode pending config: %w", err)
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyPending, encoded)
	})
	if err != nil {
		return fmt.Errorf("store: write pending config: %w", err)
	}
	return nil
}

// DesiredConfig returns what the agent should be running right now: the pending
// configuration if one was interrupted, otherwise the last confirmed one.
//
// The pending one wins because it is newer, and because the supervisor falls back to the
// configuration on disk if it cannot be started — so attempting it costs nothing that is
// not already recoverable.
func (s *Store) DesiredConfig() (config *AppliedConfig, confirmed bool, err error) {
	pending, err := s.PendingConfig()
	if err != nil {
		return nil, false, err
	}
	if pending != nil {
		return pending, false, nil
	}

	applied, err := s.AppliedConfig()
	if err != nil {
		return nil, false, err
	}
	return applied, applied != nil, nil
}

// SaveAppliedConfig records a configuration as applied.
//
// Called only after Xray has actually accepted it. Recording it earlier would mean a
// crash mid-apply leaves the agent believing a configuration is running that never
// started, and it would then never retry.
func (s *Store) SaveAppliedConfig(config *AppliedConfig) error {
	if config == nil {
		return errors.New("store: refusing to save a nil configuration")
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("store: encode applied config: %w", err)
	}

	// One transaction: confirming a configuration and forgetting the attempt are the
	// same event, and a crash between them would leave the agent retrying a
	// configuration it is already running.
	err = s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketMeta)
		if err := bucket.Put(keyConfig, encoded); err != nil {
			return err
		}
		return bucket.Delete(keyPending)
	})
	if err != nil {
		return fmt.Errorf("store: write applied config: %w", err)
	}
	return nil
}

// AppliedVersion returns the version the agent reports to the panel, or zero when it has
// confirmed nothing.
//
// A pending configuration deliberately does not count. Reporting a version the agent is
// not sure it is running would stop the panel from sending it again, which is the only
// thing that can resolve the doubt.
func (s *Store) AppliedVersion() (int64, error) {
	config, err := s.AppliedConfig()
	if err != nil || config == nil {
		return 0, err
	}
	return config.Version, nil
}
