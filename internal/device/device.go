package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

var (
	ErrInvalidDeviceID   = errors.New("invalid device ID")
	ErrInvalidSignature  = errors.New("invalid cryptographic signature")
	ErrDeviceKeysMissing = errors.New("device keys missing")
)

// DeviceKeys holds both Age encryption identity and Ed25519 signing keys for a device.
type DeviceKeys struct {
	DeviceID            string             `json:"device_id"`
	AgeIdentity         *age.X25519Identity `json:"-"`
	AgeRecipient        string             `json:"age_recipient"`
	SigningPrivateKey   ed25519.PrivateKey `json:"-"`
	SigningPublicKey    ed25519.PublicKey  `json:"-"`
	SigningPublicKeyHex string             `json:"signing_public_key"`
	Metadata            string             `json:"metadata,omitempty"`
	CreatedAt           time.Time          `json:"created_at"`
}

// GenerateDeviceID creates a unique opaque device ID string (e.g. dev_...).
func GenerateDeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "dev_" + hex.EncodeToString(b)
}

// GenerateDeviceKeys generates a new Age X25519 identity and Ed25519 signing keypair.
func GenerateDeviceKeys(metadata string) (*DeviceKeys, error) {
	ageKp, err := crypt.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed generating age keypair for device: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ed25519 signing key for device: %w", err)
	}

	devID := GenerateDeviceID()

	return &DeviceKeys{
		DeviceID:            devID,
		AgeIdentity:         ageKp.Identity,
		AgeRecipient:        ageKp.Recipient.String(),
		SigningPrivateKey:   priv,
		SigningPublicKey:    pub,
		SigningPublicKeyHex: hex.EncodeToString(pub),
		Metadata:            metadata,
		CreatedAt:           time.Now().UTC(),
	}, nil
}

// SaveDeviceKeys writes device keys securely to the local keys directory with permissions 0600.
func SaveDeviceKeys(cfg *config.Config, keys *DeviceKeys) error {
	if err := cfg.EnsureDirectories(); err != nil {
		return err
	}

	// 1. Save Age identity
	agePath := filepath.Join(cfg.KeysDir, "device.age")
	if err := crypt.SaveIdentityToFile(keys.AgeIdentity, agePath); err != nil {
		return fmt.Errorf("failed saving device age key: %w", err)
	}

	// 2. Save Ed25519 signing private key
	signingPath := filepath.Join(cfg.KeysDir, "device-signing.key")
	privHex := hex.EncodeToString(keys.SigningPrivateKey)
	if err := fsutil.WriteFileAtomic(signingPath, []byte(privHex+"\n"), 0600); err != nil {
		return fmt.Errorf("failed saving device signing key: %w", err)
	}

	// 3. Save Device metadata (public info)
	metaPath := filepath.Join(cfg.KeysDir, "device.json")
	metaBytes, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling device metadata: %w", err)
	}
	if err := fsutil.WriteFileAtomic(metaPath, metaBytes, 0600); err != nil {
		return fmt.Errorf("failed saving device metadata: %w", err)
	}

	return nil
}

// LoadDeviceKeys reads device keys from local keys directory.
func LoadDeviceKeys(cfg *config.Config) (*DeviceKeys, error) {
	agePath := filepath.Join(cfg.KeysDir, "device.age")
	signingPath := filepath.Join(cfg.KeysDir, "device-signing.key")
	metaPath := filepath.Join(cfg.KeysDir, "device.json")

	if _, err := os.Stat(agePath); os.IsNotExist(err) {
		return nil, ErrDeviceKeysMissing
	}

	// Load Age identity
	ageKp, err := crypt.LoadIdentityFromFile(agePath)
	if err != nil {
		return nil, fmt.Errorf("failed loading device age identity: %w", err)
	}

	// Load Ed25519 signing key
	privBytes, err := os.ReadFile(signingPath)
	if err != nil {
		return nil, fmt.Errorf("failed loading device signing key: %w", err)
	}
	privHex := strings.TrimSpace(string(privBytes))
	privKeyBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid device signing key content")
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Load metadata
	keys := &DeviceKeys{}
	if metaData, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(metaData, keys)
	}

	keys.AgeIdentity = ageKp.Identity
	keys.AgeRecipient = ageKp.Recipient.String()
	keys.SigningPrivateKey = privKey
	keys.SigningPublicKey = pubKey
	keys.SigningPublicKeyHex = hex.EncodeToString(pubKey)

	if keys.DeviceID == "" {
		return nil, fmt.Errorf("missing device ID in device metadata")
	}

	return keys, nil
}

// SignPayload signs a payload using Ed25519 with a domain separation prefix.
func SignPayload(privKey ed25519.PrivateKey, domain string, payload []byte) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid ed25519 private key")
	}
	full := append([]byte(domain+":"), payload...)
	sig := ed25519.Sign(privKey, full)
	return hex.EncodeToString(sig), nil
}

// VerifySignature verifies an Ed25519 signature with a domain separation prefix.
func VerifySignature(pubKeyHex string, domain string, payload []byte, sigHex string) error {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key hex", ErrInvalidSignature)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature hex", ErrInvalidSignature)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	full := append([]byte(domain+":"), payload...)

	if !ed25519.Verify(pubKey, full, sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// GetRecipientFromRecipientString parses an Age recipient string.
func GetRecipientFromRecipientString(recipStr string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(strings.TrimSpace(recipStr))
	if err != nil {
		return nil, fmt.Errorf("invalid age recipient %s: %w", recipStr, err)
	}
	return r, nil
}

// ComputePayloadHash computes SHA-256 hash of arbitrary bytes.
func ComputePayloadHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
