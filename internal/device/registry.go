package device

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	ProtocolVersionV2     = "2.0"
	DomainRegistryV2      = "agentport/registry/v2"
	DomainRecoveryV2      = "agentport/recovery/v2"
)

type DeviceStatus string

const (
	StatusActive  DeviceStatus = "active"
	StatusRevoked DeviceStatus = "revoked"
)

var (
	ErrRegistryInvalid      = errors.New("registry epoch invalid")
	ErrRegistryRollback     = errors.New("registry rollback detected")
	ErrDeviceNotAuthorized  = errors.New("device not authorized in registry")
	ErrDeviceRevoked        = errors.New("device is revoked")
	ErrDuplicateDeviceID    = errors.New("duplicate device ID in registry")
	ErrDuplicateRecipient   = errors.New("duplicate Age recipient in registry")
	ErrDuplicateSigningKey  = errors.New("duplicate signing key in registry")
)

// DeviceRecord represents an authorized public device record in the registry.
type DeviceRecord struct {
	DeviceID            string       `json:"device_id"`
	AgeRecipient        string       `json:"age_recipient"`
	SigningPublicKey    string       `json:"signing_public_key"`
	Status              DeviceStatus `json:"status"`
	AddedEpoch          uint64       `json:"added_epoch"`
	RevokedEpoch        uint64       `json:"revoked_epoch,omitempty"`
	CreatedAt           time.Time    `json:"created_at"`
	Metadata            string       `json:"metadata,omitempty"`
}

// RegistryEpoch represents one signed epoch in the device registry chain.
type RegistryEpoch struct {
	ProtocolVersion      string                   `json:"protocol_version"`
	VaultID              string                   `json:"vault_id"`
	Epoch                uint64                   `json:"epoch"`
	PreviousRegistryHash string                   `json:"previous_registry_hash"`
	ActiveDevices        map[string]*DeviceRecord `json:"active_devices"`
	RevokedDevices       map[string]*DeviceRecord `json:"revoked_devices,omitempty"`
	SignerDeviceID       string                   `json:"signer_device_id"`
	CreatedAt            time.Time                `json:"created_at"`
	Signature            string                   `json:"signature,omitempty"`
}

type canonicalRegistryPayload struct {
	ProtocolVersion      string                   `json:"protocol_version"`
	VaultID              string                   `json:"vault_id"`
	Epoch                uint64                   `json:"epoch"`
	PreviousRegistryHash string                   `json:"previous_registry_hash"`
	ActiveDevices        map[string]*DeviceRecord `json:"active_devices"`
	RevokedDevices       map[string]*DeviceRecord `json:"revoked_devices,omitempty"`
	SignerDeviceID       string                   `json:"signer_device_id"`
	CreatedAt            time.Time                `json:"created_at"`
}

// CanonicalBytes produces deterministic JSON bytes of the registry epoch excluding signature.
func (r *RegistryEpoch) CanonicalBytes() ([]byte, error) {
	payload := &canonicalRegistryPayload{
		ProtocolVersion:      r.ProtocolVersion,
		VaultID:              r.VaultID,
		Epoch:                r.Epoch,
		PreviousRegistryHash: r.PreviousRegistryHash,
		ActiveDevices:        r.ActiveDevices,
		RevokedDevices:       r.RevokedDevices,
		SignerDeviceID:       r.SignerDeviceID,
		CreatedAt:            r.CreatedAt.UTC(),
	}
	return json.Marshal(payload)
}

// ComputeRegistryHash calculates SHA-256 hash of canonical registry bytes.
func ComputeRegistryHash(epoch *RegistryEpoch) (string, error) {
	bytes, err := epoch.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

// SignRegistry signs the registry epoch using the signer device's private key.
func SignRegistry(epoch *RegistryEpoch, keys *DeviceKeys) error {
	epoch.SignerDeviceID = keys.DeviceID
	bytes, err := epoch.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("failed generating canonical bytes for registry: %w", err)
	}

	sig, err := SignPayload(keys.SigningPrivateKey, DomainRegistryV2, bytes)
	if err != nil {
		return fmt.Errorf("failed signing registry epoch: %w", err)
	}
	epoch.Signature = sig
	return nil
}

// ValidateRegistryEpoch validates a single registry epoch, optionally checking ancestry against prev.
func ValidateRegistryEpoch(epoch *RegistryEpoch, prev *RegistryEpoch) error {
	if epoch.ProtocolVersion != ProtocolVersionV2 {
		return fmt.Errorf("%w: unsupported protocol version %s", ErrRegistryInvalid, epoch.ProtocolVersion)
	}

	if epoch.VaultID == "" {
		return fmt.Errorf("%w: missing vault_id", ErrRegistryInvalid)
	}

	if epoch.Epoch == 0 {
		return fmt.Errorf("%w: epoch number must be >= 1", ErrRegistryInvalid)
	}

	if len(epoch.ActiveDevices) == 0 {
		return fmt.Errorf("%w: registry must have at least one active device", ErrRegistryInvalid)
	}

	// Uniqueness checks across active devices
	seenIDs := make(map[string]bool)
	seenRecips := make(map[string]bool)
	seenKeys := make(map[string]bool)

	for id, dev := range epoch.ActiveDevices {
		if id != dev.DeviceID {
			return fmt.Errorf("%w: active device map key %s mismatch record ID %s", ErrRegistryInvalid, id, dev.DeviceID)
		}
		if dev.Status != StatusActive {
			return fmt.Errorf("%w: active device %s has non-active status %s", ErrRegistryInvalid, dev.DeviceID, dev.Status)
		}
		if seenIDs[dev.DeviceID] {
			return fmt.Errorf("%w: %s", ErrDuplicateDeviceID, dev.DeviceID)
		}
		seenIDs[dev.DeviceID] = true

		if seenRecips[dev.AgeRecipient] {
			return fmt.Errorf("%w: %s", ErrDuplicateRecipient, dev.AgeRecipient)
		}
		seenRecips[dev.AgeRecipient] = true

		if seenKeys[dev.SigningPublicKey] {
			return fmt.Errorf("%w: %s", ErrDuplicateSigningKey, dev.SigningPublicKey)
		}
		seenKeys[dev.SigningPublicKey] = true
	}

	// Validate ancestry if prev is provided
	if prev != nil {
		if epoch.Epoch != prev.Epoch+1 {
			return fmt.Errorf("%w: expected epoch %d, got %d", ErrRegistryInvalid, prev.Epoch+1, epoch.Epoch)
		}

		prevHash, err := ComputeRegistryHash(prev)
		if err != nil {
			return err
		}

		if epoch.PreviousRegistryHash != prevHash {
			return fmt.Errorf("%w: previous registry hash mismatch", ErrRegistryInvalid)
		}

		// Signer must have been active in prev (or signer is recovery authority)
		signerInPrev, exists := prev.ActiveDevices[epoch.SignerDeviceID]
		if !exists || signerInPrev.Status != StatusActive {
			return fmt.Errorf("%w: signer %s was not active in epoch %d", ErrRegistryInvalid, epoch.SignerDeviceID, prev.Epoch)
		}

		// Validate signature using signer's public key from prev epoch
		bytes, err := epoch.CanonicalBytes()
		if err != nil {
			return err
		}

		if err := VerifySignature(signerInPrev.SigningPublicKey, DomainRegistryV2, bytes, epoch.Signature); err != nil {
			// Try recovery domain if ordinary registry domain signature fails
			if errRec := VerifySignature(signerInPrev.SigningPublicKey, DomainRecoveryV2, bytes, epoch.Signature); errRec != nil {
				return fmt.Errorf("%w: signature verification failed for signer %s: %v", ErrRegistryInvalid, epoch.SignerDeviceID, err)
			}
		}
	} else {
		// Epoch 1 (Genesis) validation
		if epoch.Epoch == 1 {
			if epoch.PreviousRegistryHash != "" {
				return fmt.Errorf("%w: epoch 1 must have empty previous_registry_hash", ErrRegistryInvalid)
			}
			signerDev, exists := epoch.ActiveDevices[epoch.SignerDeviceID]
			if !exists {
				return fmt.Errorf("%w: genesis signer %s not in active devices", ErrRegistryInvalid, epoch.SignerDeviceID)
			}
			bytes, err := epoch.CanonicalBytes()
			if err != nil {
				return err
			}
			if err := VerifySignature(signerDev.SigningPublicKey, DomainRegistryV2, bytes, epoch.Signature); err != nil {
				if errRec := VerifySignature(signerDev.SigningPublicKey, DomainRecoveryV2, bytes, epoch.Signature); errRec != nil {
					return fmt.Errorf("%w: genesis signature verification failed: %v", ErrRegistryInvalid, err)
				}
			}
		}
	}

	return nil
}

// ValidateRegistryChain checks a full sequence of epochs starting from epoch 1.
func ValidateRegistryChain(epochs []*RegistryEpoch) error {
	if len(epochs) == 0 {
		return fmt.Errorf("%w: empty registry chain", ErrRegistryInvalid)
	}

	for i, ep := range epochs {
		var prev *RegistryEpoch
		if i > 0 {
			prev = epochs[i-1]
		}
		if err := ValidateRegistryEpoch(ep, prev); err != nil {
			return fmt.Errorf("registry validation failed at index %d (epoch %d): %w", i, ep.Epoch, err)
		}
	}
	return nil
}

// ActiveRecipients returns sorted Age recipient strings for all active devices in epoch.
func (r *RegistryEpoch) ActiveRecipients() []string {
	res := make([]string, 0, len(r.ActiveDevices))
	for _, dev := range r.ActiveDevices {
		if dev.Status == StatusActive {
			res = append(res, dev.AgeRecipient)
		}
	}
	sort.Strings(res)
	return res
}

// IsDeviceActive returns true if deviceID is active in this epoch.
func (r *RegistryEpoch) IsDeviceActive(deviceID string) bool {
	dev, ok := r.ActiveDevices[deviceID]
	return ok && dev.Status == StatusActive
}
