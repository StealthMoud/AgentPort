package device

import (
	"crypto/ed25519"
	"crypto/rand"
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
	ErrRecoveryInvalid = errors.New("invalid recovery authority or bundle")
)

type RecoveryAuthority struct {
	AuthorityID         string             `json:"authority_id"`
	AgeIdentity         *age.X25519Identity `json:"-"`
	AgeRecipient        string             `json:"age_recipient"`
	SigningPrivateKey   ed25519.PrivateKey `json:"-"`
	SigningPublicKey    ed25519.PublicKey  `json:"-"`
	SigningPublicKeyHex string             `json:"signing_public_key"`
	CreatedAt           time.Time          `json:"created_at"`
}

// GenerateRecoveryAuthority generates an offline recovery authority identity.
func GenerateRecoveryAuthority() (*RecoveryAuthority, error) {
	ageKp, err := crypt.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed generating recovery age keypair: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating recovery ed25519 key: %w", err)
	}

	b := make([]byte, 12)
	_, _ = rand.Read(b)
	authID := "rec_" + hex.EncodeToString(b)

	return &RecoveryAuthority{
		AuthorityID:         authID,
		AgeIdentity:         ageKp.Identity,
		AgeRecipient:        ageKp.Recipient.String(),
		SigningPrivateKey:   priv,
		SigningPublicKey:    pub,
		SigningPublicKeyHex: hex.EncodeToString(pub),
		CreatedAt:           time.Now().UTC(),
	}, nil
}

// RecoveryBundleData contains the raw private credentials needed for disaster recovery.
type RecoveryBundleData struct {
	ProtocolVersion     string    `json:"protocol_version"`
	VaultID             string    `json:"vault_id"`
	AuthorityID         string    `json:"authority_id"`
	AgeIdentitySecret   string    `json:"age_identity_secret"`
	SigningPrivateKeyHex string   `json:"signing_private_key"`
	CreatedAt           time.Time `json:"created_at"`
}

// ExportRecoveryBundle encrypts recovery credentials using a passphrase recipient or key into a file.
func ExportRecoveryBundle(auth *RecoveryAuthority, vaultID, outputPath, passphrase string) error {
	if auth == nil || auth.AgeIdentity == nil || len(auth.SigningPrivateKey) == 0 {
		return ErrRecoveryInvalid
	}

	data := &RecoveryBundleData{
		ProtocolVersion:      ProtocolVersionV2,
		VaultID:              vaultID,
		AuthorityID:          auth.AuthorityID,
		AgeIdentitySecret:    auth.AgeIdentity.String(),
		SigningPrivateKeyHex: hex.EncodeToString(auth.SigningPrivateKey),
		CreatedAt:            time.Now().UTC(),
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	var ciphertext []byte
	if passphrase != "" {
		recipient, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return fmt.Errorf("failed creating passphrase recipient: %w", err)
		}
		ciphertext, err = crypt.Encrypt(recipient, jsonBytes)
		if err != nil {
			return fmt.Errorf("failed encrypting recovery bundle: %w", err)
		}
	} else {
		// Encrypt to recovery Age recipient itself as fallback
		recipient, err := age.ParseX25519Recipient(auth.AgeRecipient)
		if err != nil {
			return err
		}
		ciphertext, err = crypt.Encrypt(recipient, jsonBytes)
		if err != nil {
			return fmt.Errorf("failed encrypting recovery bundle: %w", err)
		}
	}

	return fsutil.WriteFileAtomic(outputPath, ciphertext, 0600)
}

// ImportRecoveryBundle decrypts and parses a recovery bundle file.
func ImportRecoveryBundle(bundlePath, passphrase string, fallbackIdentity *age.X25519Identity) (*RecoveryAuthority, string, error) {
	ciphertext, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading recovery bundle file: %w", err)
	}

	var plaintext []byte
	if passphrase != "" {
		identity, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, "", fmt.Errorf("invalid passphrase: %w", err)
		}
		plaintext, err = crypt.Decrypt(identity, ciphertext)
		if err != nil {
			return nil, "", fmt.Errorf("%w: decryption with passphrase failed: %v", ErrRecoveryInvalid, err)
		}
	} else if fallbackIdentity != nil {
		plaintext, err = crypt.Decrypt(fallbackIdentity, ciphertext)
		if err != nil {
			return nil, "", fmt.Errorf("%w: decryption with identity failed: %v", ErrRecoveryInvalid, err)
		}
	} else {
		return nil, "", fmt.Errorf("%w: passphrase or identity required to decrypt recovery bundle", ErrRecoveryInvalid)
	}

	bundle := &RecoveryBundleData{}
	if err := json.Unmarshal(plaintext, bundle); err != nil {
		return nil, "", fmt.Errorf("%w: corrupt bundle JSON: %v", ErrRecoveryInvalid, err)
	}

	ageId, err := age.ParseX25519Identity(bundle.AgeIdentitySecret)
	if err != nil {
		return nil, "", fmt.Errorf("%w: invalid age identity in bundle: %v", ErrRecoveryInvalid, err)
	}

	privKeyBytes, err := hex.DecodeString(bundle.SigningPrivateKeyHex)
	if err != nil || len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("%w: invalid signing key in bundle", ErrRecoveryInvalid)
	}
	privKey := ed25519.PrivateKey(privKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	auth := &RecoveryAuthority{
		AuthorityID:         bundle.AuthorityID,
		AgeIdentity:         ageId,
		AgeRecipient:        ageId.Recipient().String(),
		SigningPrivateKey:   privKey,
		SigningPublicKey:    pubKey,
		SigningPublicKeyHex: hex.EncodeToString(pubKey),
		CreatedAt:           bundle.CreatedAt,
	}

	return auth, bundle.VaultID, nil
}

// SaveRecoveryPublicConfig saves public recovery authority info to local keys dir.
func SaveRecoveryPublicConfig(cfg *config.Config, auth *RecoveryAuthority) error {
	pubPath := filepath.Join(cfg.KeysDir, "recovery_public.json")
	data := map[string]string{
		"authority_id":       auth.AuthorityID,
		"age_recipient":      auth.AgeRecipient,
		"signing_public_key": auth.SigningPublicKeyHex,
	}
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(pubPath, bytes, 0600)
}

// LoadRecoveryPublicConfig reads public recovery info if configured.
func LoadRecoveryPublicConfig(cfg *config.Config) (recipient string, signingKeyHex string, authID string, err error) {
	pubPath := filepath.Join(cfg.KeysDir, "recovery_public.json")
	bytes, err := os.ReadFile(pubPath)
	if err != nil {
		return "", "", "", err
	}
	m := make(map[string]string)
	if err := json.Unmarshal(bytes, &m); err != nil {
		return "", "", "", err
	}
	return strings.TrimSpace(m["age_recipient"]), strings.TrimSpace(m["signing_public_key"]), strings.TrimSpace(m["authority_id"]), nil
}
