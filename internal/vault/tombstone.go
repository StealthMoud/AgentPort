package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
)

type TombstoneStore struct {
	mu         sync.RWMutex
	v          *Vault
	tombstones map[string]*model.Tombstone
}

func NewTombstoneStore(v *Vault) *TombstoneStore {
	return &TombstoneStore{
		v:          v,
		tombstones: make(map[string]*model.Tombstone),
	}
}

// RecordTombstone creates and persists a tombstone for a deleted entity.
func (v *Vault) RecordTombstone(entityID string, prevRevHash string) (*model.Tombstone, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	ts := &model.Tombstone{
		EntityID:             entityID,
		DeletedRevision:      1,
		DeletedAt:            time.Now(),
		OriginMachineID:      v.Machine.MachineID,
		PreviousRevisionHash: prevRevHash,
	}

	tombDir := filepath.Join(v.cfg.VaultDir, "tombstones")
	if err := os.MkdirAll(tombDir, 0700); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(tombDir, entityID+".json")
	if err := fsutil.WriteFileAtomic(filePath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed persisting tombstone for %s: %w", entityID, err)
	}

	return ts, nil
}

// GetTombstone retrieves a tombstone if existing.
func (v *Vault) GetTombstone(entityID string) (*model.Tombstone, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	tombDir := filepath.Join(v.cfg.VaultDir, "tombstones")
	filePath := filepath.Join(tombDir, entityID+".json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	ts := &model.Tombstone{}
	if err := json.Unmarshal(data, ts); err != nil {
		return nil, false
	}

	return ts, true
}

// ListTombstones lists all active tombstones in vault.
func (v *Vault) ListTombstones() ([]*model.Tombstone, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	tombDir := filepath.Join(v.cfg.VaultDir, "tombstones")
	if _, err := os.Stat(tombDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(tombDir)
	if err != nil {
		return nil, err
	}

	res := make([]*model.Tombstone, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tombDir, entry.Name()))
		if err != nil {
			continue
		}
		ts := &model.Tombstone{}
		if err := json.Unmarshal(data, ts); err == nil {
			res = append(res, ts)
		}
	}

	return res, nil
}
