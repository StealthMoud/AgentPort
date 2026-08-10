package syncv2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

const (
	ProtocolFileName = "protocol.json"
	RegistryDir      = "registry"
	RegistryHeadFile = "registry-head.json"
	PairingDir       = "pairing"
	CatalogHeadFile  = "catalog-head.json"
	CatalogsDir      = "catalogs"
	ObjectsDir       = "objects"
)

// ProtocolMetadata represents non-sensitive V2 remote transport protocol metadata.
type ProtocolMetadata struct {
	ProtocolVersion  string `json:"protocol_version"`
	VaultID          string `json:"vault_id"`
	RegistryHeadHash string `json:"registry_head_hash,omitempty"`
	RegistryEpoch    uint64 `json:"registry_epoch,omitempty"`
	CatalogHeadID    string `json:"catalog_head_id,omitempty"`
}

// WriteProtocolMetadata writes protocol.json to the sync repository dir with 0600 permissions.
func WriteProtocolMetadata(repoDir string, meta *ProtocolMetadata) error {
	meta.ProtocolVersion = "2.0"
	bytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(repoDir, ProtocolFileName), bytes, 0600)
}

// ReadProtocolMetadata reads protocol.json from the sync repository dir.
func ReadProtocolMetadata(repoDir string) (*ProtocolMetadata, error) {
	path := filepath.Join(repoDir, ProtocolFileName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading protocol.json: %w", err)
	}
	meta := &ProtocolMetadata{}
	if err := json.Unmarshal(bytes, meta); err != nil {
		return nil, fmt.Errorf("corrupt protocol.json: %w", err)
	}
	return meta, nil
}

// EnsureRepoStructure initializes required subdirectories in the remote transport checkout.
func EnsureRepoStructure(repoDir string) error {
	dirs := []string{
		filepath.Join(repoDir, RegistryDir),
		filepath.Join(repoDir, PairingDir, "requests"),
		filepath.Join(repoDir, PairingDir, "approvals"),
		filepath.Join(repoDir, CatalogsDir),
		filepath.Join(repoDir, ObjectsDir),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}
