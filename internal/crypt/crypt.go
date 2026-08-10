package crypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

var (
	ErrInvalidKey       = errors.New("invalid age key")
	ErrDecryptionFailed = errors.New("decryption failed - wrong identity or corrupt data")
	ErrMissingIdentity  = errors.New("encryption identity missing")
	ErrNoRecipients     = errors.New("no recipients provided")
	ErrInvalidRecipient = errors.New("invalid age recipient")
)

// KeyPair represents Age private identity and public recipient.
type KeyPair struct {
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// GenerateKeyPair generates a new X25519 Age key pair.
func GenerateKeyPair() (*KeyPair, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed generating age identity: %w", err)
	}

	recipient := identity.Recipient()

	return &KeyPair{
		Identity:  identity,
		Recipient: recipient,
	}, nil
}

// SaveIdentityToFile writes private identity string to file with permissions 0600.
func SaveIdentityToFile(identity *age.X25519Identity, path string) error {
	secretStr := identity.String()
	return fsutil.WriteFileAtomic(path, []byte(secretStr+"\n"), 0600)
}

// LoadIdentityFromFile reads private identity string from file and parses it.
func LoadIdentityFromFile(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading identity file: %w", err)
	}

	secretStr := strings.TrimSpace(string(data))
	identity, err := age.ParseX25519Identity(secretStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	return &KeyPair{
		Identity:  identity,
		Recipient: identity.Recipient(),
	}, nil
}

// Encrypt encrypts plaintext data using an Age recipient.
func Encrypt(recipient age.Recipient, plaintext []byte) ([]byte, error) {
	return EncryptToRecipients([]age.Recipient{recipient}, plaintext)
}

// EncryptToRecipients encrypts plaintext data using one or more Age recipients.
// Rejects zero recipients, invalid/nil recipients, and deduplicates identical recipients.
func EncryptToRecipients(recipients []age.Recipient, plaintext []byte) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}

	dedup := make([]age.Recipient, 0, len(recipients))
	seen := make(map[string]bool)

	for _, r := range recipients {
		if r == nil {
			return nil, ErrInvalidRecipient
		}
		str := fmt.Sprintf("%v", r)
		if !seen[str] {
			seen[str] = true
			dedup = append(dedup, r)
		}
	}

	if len(dedup) == 0 {
		return nil, ErrNoRecipients
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, dedup...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize age encryption: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed writing plaintext to age encryptor: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed closing age encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// RecipientSetHash returns a deterministic SHA-256 digest of sorted public recipient strings.
func RecipientSetHash(recipients []string) string {
	if len(recipients) == 0 {
		return ""
	}
	cp := make([]string, len(recipients))
	copy(cp, recipients)
	sort.Strings(cp)
	joined := strings.Join(cp, "\n")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

// Decrypt decrypts ciphertext data using an Age identity.
func Decrypt(identity age.Identity, ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: read failed: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
