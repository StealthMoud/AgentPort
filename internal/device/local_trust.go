package device

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

// LocalTrustAnchor stores locally verified trust state to prevent rollback attacks.
type LocalTrustAnchor struct {
	VaultID               string `json:"vault_id"`
	HighestRegistryEpoch  uint64 `json:"highest_registry_epoch"`
	RegistryHeadHash      string `json:"registry_head_hash"`
	LastAcceptedCatalogID string `json:"last_accepted_catalog_id,omitempty"`
}

func getTrustAnchorPath(cfg *config.Config) string {
	return filepath.Join(cfg.HomeDir, "local", "device_trust.json")
}

// LoadTrustAnchor loads the machine-local trust anchor file if it exists.
func LoadTrustAnchor(cfg *config.Config) (*LocalTrustAnchor, error) {
	path := getTrustAnchorPath(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &LocalTrustAnchor{}, nil
		}
		return nil, fmt.Errorf("failed reading local trust anchor: %w", err)
	}

	trust := &LocalTrustAnchor{}
	if err := json.Unmarshal(data, trust); err != nil {
		return nil, fmt.Errorf("corrupt local trust anchor: %w", err)
	}
	return trust, nil
}

// SaveTrustAnchor writes local trust anchor file with 0600 permissions.
func SaveTrustAnchor(cfg *config.Config, trust *LocalTrustAnchor) error {
	localDir := filepath.Join(cfg.HomeDir, "local")
	if err := os.MkdirAll(localDir, 0700); err != nil {
		return err
	}

	path := getTrustAnchorPath(cfg)
	data, err := json.MarshalIndent(trust, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling trust anchor: %w", err)
	}

	return fsutil.WriteFileAtomic(path, data, 0600)
}

// VerifyAgainstTrustAnchor checks an incoming registry epoch against the local trust anchor.
func VerifyAgainstTrustAnchor(trust *LocalTrustAnchor, epoch *RegistryEpoch) error {
	if trust == nil || trust.HighestRegistryEpoch == 0 {
		return nil // First setup on this device
	}

	if trust.VaultID != "" && trust.VaultID != epoch.VaultID {
		return fmt.Errorf("%w: vault ID mismatch (local: %s, incoming: %s)", ErrRegistryInvalid, trust.VaultID, epoch.VaultID)
	}

	if epoch.Epoch < trust.HighestRegistryEpoch {
		return fmt.Errorf("%w: incoming epoch %d is lower than locally accepted epoch %d", ErrRegistryRollback, epoch.Epoch, trust.HighestRegistryEpoch)
	}

	return nil
}
