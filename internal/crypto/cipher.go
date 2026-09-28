// Package crypto holds the primitives the panel needs: authenticated encryption
// for secrets stored in the database, password hashing, and random identifiers.
//
// Nothing here invents a construction. Every function is a thin, opinionated
// wrapper whose job is to make the safe call the only convenient one.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the required length of the master key in bytes.
const KeySize = 32

// cipherVersion prefixes every ciphertext. It exists so that a future change of
// algorithm or key-derivation scheme can be rolled out by writing version 2 while
// still reading version 1, instead of requiring a flag day.
const cipherVersion byte = 1

// ErrInvalidKeySize is returned when a key is not exactly [KeySize] bytes.
var ErrInvalidKeySize = fmt.Errorf("crypto: key must be exactly %d bytes", KeySize)

// ErrMalformedCiphertext is returned when stored bytes cannot be a ciphertext
// this package produced.
var ErrMalformedCiphertext = errors.New("crypto: malformed ciphertext")

// ErrUnsupportedVersion is returned when a ciphertext carries a version this
// build does not know how to read.
var ErrUnsupportedVersion = errors.New("crypto: unsupported ciphertext version")

// ErrDecryptFailed is returned when authentication fails. It deliberately says
// nothing about why: the distinction between a wrong key, a wrong purpose and a
// tampered payload is useful to an attacker and useless to an operator.
var ErrDecryptFailed = errors.New("crypto: decryption failed")

// Cipher encrypts small secrets for storage in the database: the CA private key,
// Reality private keys, TOTP secrets, webhook secrets.
//
// It is safe for concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a cipher from a 32-byte master key.
//
// The key is used directly rather than stretched, because it is expected to be 32
// bytes of output from a CSPRNG (see PANEL_SECRET_KEY), not a human-chosen
// passphrase. Config validation rejects anything shorter, so a weak key cannot
// reach this point.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext, binding it to purpose.
//
// purpose is authenticated but not encrypted, and acts as domain separation: a
// ciphertext sealed as "reality.private_key" will not decrypt as "pki.ca_key".
// That turns "someone copied a value between two columns" from a silent success
// into a loud failure.
func (c *Cipher) Encrypt(plaintext []byte, purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("crypto: purpose must not be empty")
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}

	// Layout: version || nonce || ciphertext+tag.
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, cipherVersion)
	out = append(out, nonce...)
	out = c.aead.Seal(out, nonce, plaintext, []byte(purpose))
	return out, nil
}

// Decrypt opens a ciphertext produced by [Cipher.Encrypt] with the same purpose.
func (c *Cipher) Decrypt(ciphertext []byte, purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("crypto: purpose must not be empty")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < 1+nonceSize+c.aead.Overhead() {
		return nil, ErrMalformedCiphertext
	}
	if ciphertext[0] != cipherVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, ciphertext[0])
	}

	nonce := ciphertext[1 : 1+nonceSize]
	sealed := ciphertext[1+nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, sealed, []byte(purpose))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// EncryptString is a convenience wrapper for secrets that are naturally text.
func (c *Cipher) EncryptString(plaintext, purpose string) ([]byte, error) {
	return c.Encrypt([]byte(plaintext), purpose)
}

// DecryptString is the inverse of [Cipher.EncryptString].
func (c *Cipher) DecryptString(ciphertext []byte, purpose string) (string, error) {
	plaintext, err := c.Decrypt(ciphertext, purpose)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DeriveKey derives a subkey from the master key for a named purpose using
// HKDF-SHA256.
//
// This is why the panel needs one secret rather than several: the JWT signing key
// and any future keyed primitive come from PANEL_SECRET_KEY, while staying
// cryptographically independent of the database encryption key and of each other.
func DeriveKey(master []byte, purpose string, size int) ([]byte, error) {
	if len(master) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if purpose == "" {
		return nil, errors.New("crypto: purpose must not be empty")
	}
	if size <= 0 || size > 1024 {
		return nil, fmt.Errorf("crypto: derived key size %d out of range", size)
	}

	// No salt: the master key is already full-entropy random, and a fixed empty
	// salt keeps derivation deterministic across restarts, which it must be.
	out := make([]byte, size)
	reader := hkdf.New(sha256.New, master, nil, []byte("xraypanel/v1/"+purpose))
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return out, nil
}
