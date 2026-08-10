package snapshot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

var (
	ErrSnapshotNotFound = errors.New("snapshot not found")
)

type SnapshotMetadata struct {
	SnapshotID            string    `json:"snapshot_id"`
	CreatedAt             time.Time `json:"created_at"`
	VaultID               string    `json:"vault_id"`
	ArtifactCount         int       `json:"artifact_count"`
	EntityCount           int       `json:"entity_count"`
	Reason                string    `json:"reason"`
	VaultStateFingerprint string    `json:"vault_state_fingerprint"`
}

type Manager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func generateSnapshotID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("snap_%d_%s", time.Now().Unix(), hex.EncodeToString(b))
}

// CreateSnapshot creates a complete backup snapshot of local vault V1 artifacts and V2 entities.
func (m *Manager) CreateSnapshot(v *vault.Vault, reason string) (*SnapshotMetadata, error) {
	snapID := generateSnapshotID()
	snapDir := filepath.Join(m.cfg.SnapshotsDir, snapID)
	artifactsDir := filepath.Join(snapDir, "artifacts")
	entitiesDir := filepath.Join(snapDir, "entities")

	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating snapshot artifacts directory: %w", err)
	}
	if err := os.MkdirAll(entitiesDir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating snapshot entities directory: %w", err)
	}

	// 1. Save V1 artifacts
	artifacts := v.ListArtifacts()
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].ID < artifacts[j].ID
	})

	for _, art := range artifacts {
		data, err := json.MarshalIndent(art, "", "  ")
		if err != nil {
			return nil, err
		}
		artPath := filepath.Join(artifactsDir, art.ID+".json")
		if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed writing snapshot artifact %s: %w", art.ID, err)
		}
	}

	// 2. Save V2 entities
	entities := v.ListEntities()
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].ID < entities[j].ID
	})

	for _, env := range entities {
		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return nil, err
		}
		envPath := filepath.Join(entitiesDir, env.ID+".json")
		if err := fsutil.WriteFileAtomic(envPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed writing snapshot entity %s: %w", env.ID, err)
		}
	}

	stateFp := model.ComputeV2StateRoot(entities)
	if len(entities) == 0 {
		var totalFingerprints string
		for _, art := range artifacts {
			totalFingerprints += art.ID + ":" + art.Fingerprint + "|"
		}
		stateFp = model.ComputeFingerprint(model.KindMemory, model.ScopeGlobal, "vault_state", totalFingerprints, nil)
	}

	meta := &SnapshotMetadata{
		SnapshotID:            snapID,
		CreatedAt:             time.Now(),
		VaultID:               v.Metadata.VaultID,
		ArtifactCount:         len(artifacts),
		EntityCount:           len(entities),
		Reason:                reason,
		VaultStateFingerprint: stateFp,
	}

	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}

	metaPath := filepath.Join(snapDir, "snapshot.json")
	if err := fsutil.WriteFileAtomic(metaPath, metaData, 0600); err != nil {
		return nil, err
	}

	return meta, nil
}

// ListSnapshots returns all available snapshots sorted by creation time (newest first).
func (m *Manager) ListSnapshots() ([]*SnapshotMetadata, error) {
	if _, err := os.Stat(m.cfg.SnapshotsDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(m.cfg.SnapshotsDir)
	if err != nil {
		return nil, err
	}

	var res []*SnapshotMetadata

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(m.cfg.SnapshotsDir, entry.Name(), "snapshot.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		meta := &SnapshotMetadata{}
		if err := json.Unmarshal(data, meta); err == nil {
			res = append(res, meta)
		}
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})

	return res, nil
}

// RestoreSnapshot restores vault artifacts and V2 entities state from a snapshot using transactional staging.
func (m *Manager) RestoreSnapshot(v *vault.Vault, snapshotID string) error {
	snapDir := filepath.Join(m.cfg.SnapshotsDir, snapshotID)
	artifactsDir := filepath.Join(snapDir, "artifacts")
	entitiesDir := filepath.Join(snapDir, "entities")

	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		return ErrSnapshotNotFound
	}

	// 1. Read staged V1 artifacts
	stagedArtifacts := make([]*model.Artifact, 0)
	if entries, err := os.ReadDir(artifactsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(artifactsDir, entry.Name()))
			if err != nil {
				return fmt.Errorf("failed reading snapshot artifact %s: %w", entry.Name(), err)
			}
			art := &model.Artifact{}
			if err := json.Unmarshal(data, art); err != nil {
				return fmt.Errorf("failed parsing snapshot artifact %s: %w", entry.Name(), err)
			}
			stagedArtifacts = append(stagedArtifacts, art)
		}
	}

	// 2. Read staged V2 entities
	stagedEntities := make([]*model.EnvelopeV2, 0)
	if entries, err := os.ReadDir(entitiesDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(entitiesDir, entry.Name()))
			if err != nil {
				return fmt.Errorf("failed reading snapshot entity %s: %w", entry.Name(), err)
			}
			env := &model.EnvelopeV2{}
			if err := json.Unmarshal(data, env); err != nil {
				return fmt.Errorf("failed parsing snapshot entity %s: %w", entry.Name(), err)
			}
			stagedEntities = append(stagedEntities, env)
		}
	}

	// 3. Perform atomic transaction restore
	tx := v.BeginTx()

	// Clear current V1 artifacts and V2 entities
	for _, art := range v.ListArtifacts() {
		if err := tx.DeleteArtifact(art.ID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for _, env := range v.ListEntities() {
		if err := tx.DeleteEntity(env.ID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	// Save staged V1 artifacts
	for _, art := range stagedArtifacts {
		if err := tx.SaveArtifact(art); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	// Save staged V2 entities
	for _, env := range stagedEntities {
		if err := tx.SaveEntity(env); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed committing snapshot restore transaction: %w", err)
	}

	return nil
}
