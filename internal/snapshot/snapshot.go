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

// CreateSnapshot creates a complete backup snapshot of local vault artifacts.
func (m *Manager) CreateSnapshot(v *vault.Vault, reason string) (*SnapshotMetadata, error) {
	snapID := generateSnapshotID()
	snapDir := filepath.Join(m.cfg.SnapshotsDir, snapID)
	artifactsDir := filepath.Join(snapDir, "artifacts")

	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating snapshot directory: %w", err)
	}

	artifacts := v.ListArtifacts()
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].ID < artifacts[j].ID
	})

	var totalFingerprints string
	for _, art := range artifacts {
		totalFingerprints += art.ID + ":" + art.Fingerprint + "|"
		data, err := json.MarshalIndent(art, "", "  ")
		if err != nil {
			return nil, err
		}
		artPath := filepath.Join(artifactsDir, art.ID+".json")
		if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed writing snapshot artifact %s: %w", art.ID, err)
		}
	}

	stateFp := model.ComputeFingerprint(model.KindMemory, model.ScopeGlobal, "vault_state", totalFingerprints, nil)

	meta := &SnapshotMetadata{
		SnapshotID:            snapID,
		CreatedAt:             time.Now(),
		VaultID:               v.Metadata.VaultID,
		ArtifactCount:         len(artifacts),
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

// RestoreSnapshot restores vault artifacts state from a snapshot using transactional staging.
func (m *Manager) RestoreSnapshot(v *vault.Vault, snapshotID string) error {
	snapDir := filepath.Join(m.cfg.SnapshotsDir, snapshotID)
	artifactsDir := filepath.Join(snapDir, "artifacts")

	if _, err := os.Stat(artifactsDir); os.IsNotExist(err) {
		return ErrSnapshotNotFound
	}

	// 1. Read and validate all snapshot artifacts into memory first
	entries, err := os.ReadDir(artifactsDir)
	if err != nil {
		return err
	}

	stagedArtifacts := make([]*model.Artifact, 0, len(entries))
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
		if err := art.Validate(); err != nil {
			return fmt.Errorf("snapshot artifact %s validation failed: %w", entry.Name(), err)
		}
		stagedArtifacts = append(stagedArtifacts, art)
	}

	// 2. Create safety backup snapshot before applying restoration
	_, _ = m.CreateSnapshot(v, "Pre-restore safety backup")

	// 3. Perform atomic transaction restore
	tx := v.BeginTx()
	currentArtifacts := v.ListArtifacts()
	for _, art := range currentArtifacts {
		if err := tx.DeleteArtifact(art.ID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	for _, art := range stagedArtifacts {
		if err := tx.SaveArtifact(art); err != nil {
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
