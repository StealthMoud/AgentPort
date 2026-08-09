package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

var (
	ErrInvalidKey       = errors.New("invalid age key")
	ErrDecryptionFailed = errors.New("decryption failed - wrong identity or corrupt data")
	ErrMissingIdentity  = errors.New("encryption identity missing")
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
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
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
