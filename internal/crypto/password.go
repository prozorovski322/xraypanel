package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash is returned when a stored password hash is not in the expected
// PHC format. It means the row is corrupt or was written by another tool, not
// that the password was wrong.
var ErrInvalidHash = errors.New("crypto: invalid password hash format")

// ErrIncompatibleVersion is returned when a hash was produced by a different
// Argon2 version than this build understands.
var ErrIncompatibleVersion = errors.New("crypto: incompatible argon2 version")

// Argon2Params are the cost parameters of a single hash. They are stored inside
// every hash string, so changing the defaults does not invalidate existing
// passwords: old hashes keep verifying with their own parameters and are flagged
// for rehash on the next successful login.
type Argon2Params struct {
	// Memory in KiB.
	Memory uint32
	// Iterations is the time cost.
	Iterations uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	// SaltLength in bytes.
	SaltLength uint32
	// KeyLength in bytes.
	KeyLength uint32
}

// DefaultArgon2Params returns the cost parameters used for new passwords.
//
// 64 MiB with three passes sits above the usual OWASP floor for Argon2id while
// staying affordable on a small VPS. It is affordable specifically because the
// login endpoint is rate limited and locked out after a handful of failures: cost
// parameters are the second line of defence, not the first.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword hashes a password with Argon2id and encodes it in PHC string
// format, the same layout the reference implementation uses:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func HashPassword(password string, params Argon2Params) (string, error) {
	if password == "" {
		return "", errors.New("crypto: password must not be empty")
	}
	if err := params.validate(); err != nil {
		return "", err
	}

	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("crypto: read salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against an encoded hash.
//
// It returns whether the password matches and whether the hash should be
// recomputed because it was produced with weaker parameters than the current
// defaults. The caller rehashes on a successful login, which upgrades stored
// hashes gradually without asking anyone to change their password.
//
// A non-nil error means the stored hash is unusable, which is a different problem
// from a wrong password and must not be reported to the user as one.
func VerifyPassword(password, encoded string) (match, needsRehash bool, err error) {
	stored, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}

	computed := argon2.IDKey(
		[]byte(password),
		salt,
		stored.Iterations,
		stored.Memory,
		stored.Parallelism,
		uint32(len(key)),
	)

	if subtle.ConstantTimeCompare(key, computed) != 1 {
		return false, false, nil
	}
	return true, stored.weakerThan(DefaultArgon2Params()), nil
}

func (p Argon2Params) validate() error {
	switch {
	case p.Memory < 8*1024:
		return fmt.Errorf("crypto: argon2 memory %d KiB is below the 8192 KiB floor", p.Memory)
	case p.Iterations < 1:
		return errors.New("crypto: argon2 iterations must be at least 1")
	case p.Parallelism < 1:
		return errors.New("crypto: argon2 parallelism must be at least 1")
	case p.SaltLength < 16:
		return fmt.Errorf("crypto: argon2 salt length %d is below the 16 byte floor", p.SaltLength)
	case p.KeyLength < 16:
		return fmt.Errorf("crypto: argon2 key length %d is below the 16 byte floor", p.KeyLength)
	}
	return nil
}

// weakerThan reports whether any cost parameter falls short of want.
func (p Argon2Params) weakerThan(want Argon2Params) bool {
	return p.Memory < want.Memory ||
		p.Iterations < want.Iterations ||
		p.KeyLength < want.KeyLength ||
		p.SaltLength < want.SaltLength
}

// decodeHash parses a PHC-format Argon2id hash.
func decodeHash(encoded string) (params Argon2Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// An empty leading field comes from the leading "$".
	if len(parts) != 6 || parts[0] != "" {
		return params, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return params, nil, nil, fmt.Errorf("%w: algorithm %q is not argon2id", ErrInvalidHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return params, nil, nil, fmt.Errorf("%w: got %d, want %d", ErrIncompatibleVersion, version, argon2.Version)
	}

	memory, iterations, parallelism, err := parseCostParams(parts[3])
	if err != nil {
		return params, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, fmt.Errorf("%w: salt is not raw base64", ErrInvalidHash)
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, fmt.Errorf("%w: key is not raw base64", ErrInvalidHash)
	}
	if len(salt) == 0 || len(key) == 0 {
		return params, nil, nil, ErrInvalidHash
	}

	return Argon2Params{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(key)),
	}, salt, key, nil
}

// parseCostParams reads the "m=65536,t=3,p=2" field.
//
// It is parsed field by field rather than with Sscanf so that a reordered or
// truncated field is rejected instead of silently leaving a zero cost in place,
// which would make every hash trivial to attack.
func parseCostParams(field string) (memory, iterations uint32, parallelism uint8, err error) {
	var seenMemory, seenIterations, seenParallelism bool

	for _, kv := range strings.Split(field, ",") {
		name, value, found := strings.Cut(kv, "=")
		if !found {
			return 0, 0, 0, ErrInvalidHash
		}
		n, convErr := strconv.ParseUint(value, 10, 32)
		if convErr != nil {
			return 0, 0, 0, ErrInvalidHash
		}
		switch name {
		case "m":
			memory, seenMemory = uint32(n), true
		case "t":
			iterations, seenIterations = uint32(n), true
		case "p":
			if n > 255 {
				return 0, 0, 0, ErrInvalidHash
			}
			parallelism, seenParallelism = uint8(n), true
		default:
			return 0, 0, 0, fmt.Errorf("%w: unknown cost parameter %q", ErrInvalidHash, name)
		}
	}

	if !seenMemory || !seenIterations || !seenParallelism {
		return 0, 0, 0, ErrInvalidHash
	}
	if memory == 0 || iterations == 0 || parallelism == 0 {
		return 0, 0, 0, ErrInvalidHash
	}
	return memory, iterations, parallelism, nil
}
