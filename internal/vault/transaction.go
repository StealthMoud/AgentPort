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
	"github.com/StealthMoud/AgentPort/internal/security"
)

// Tx represents an in-memory staged transaction for atomic vault mutations.
type Tx struct {
	mu         sync.Mutex
	v          *Vault
	staged     map[string]*model.Artifact
	deletions  map[string]bool
	committed  bool
	rolledBack bool
}

// BeginTx starts a new transaction against the vault.
func (v *Vault) BeginTx() *Tx {
	return &Tx{
		v:         v,
		staged:    make(map[string]*model.Artifact),
		deletions: make(map[string]bool),
	}
}

// SaveArtifact stages an artifact write in the transaction.
func (tx *Tx) SaveArtifact(art *model.Artifact) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return fmt.Errorf("transaction already finished")
	}

	cloned := art.Clone()
	cloned.UpdateFingerprint()

	if cloned.ID == "" {
		cloned.ID = model.GenerateArtifactID(cloned.Kind, cloned.Fingerprint)
	}

	if err := cloned.Validate(); err != nil {
		return err
	}

	if err := security.ValidateArtifactSecurity(cloned); err != nil {
		return err
	}

	if cloned.CreatedAt.IsZero() {
		cloned.CreatedAt = time.Now()
	}
	cloned.UpdatedAt = time.Now()

	art.ID = cloned.ID
	art.Fingerprint = cloned.Fingerprint

	tx.staged[cloned.ID] = cloned
	delete(tx.deletions, cloned.ID)
	return nil
}

// DeleteArtifact stages an artifact deletion in the transaction.
func (tx *Tx) DeleteArtifact(id string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return fmt.Errorf("transaction already finished")
	}

	delete(tx.staged, id)
	tx.deletions[id] = true
	return nil
}

// Commit validates all staged mutations and atomically applies them to disk and memory.
func (tx *Tx) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return fmt.Errorf("transaction already finished")
	}

	// 1. Complete validation pass
	for id, art := range tx.staged {
		if err := art.Validate(); err != nil {
			return fmt.Errorf("transaction commit validation failed for %s: %w", id, err)
		}
		if err := security.ValidateArtifactSecurity(art); err != nil {
			return fmt.Errorf("transaction commit security check failed for %s: %w", id, err)
		}
	}

	// 2. Lock vault for atomic state update
	tx.v.mu.Lock()
	defer tx.v.mu.Unlock()

	artifactsDir := filepath.Join(tx.v.cfg.VaultDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return fmt.Errorf("failed creating artifacts directory: %w", err)
	}

	var writtenPaths []string

	for id, art := range tx.staged {
		artPath := filepath.Join(artifactsDir, id+".json")
		data, err := json.MarshalIndent(art, "", "  ")
		if err != nil {
			// Rollback written files on failure
			for _, p := range writtenPaths {
				_ = os.Remove(p)
			}
			return fmt.Errorf("failed marshaling artifact %s: %w", id, err)
		}

		if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
			for _, p := range writtenPaths {
				_ = os.Remove(p)
			}
			return fmt.Errorf("failed atomic write for artifact %s: %w", id, err)
		}
		writtenPaths = append(writtenPaths, artPath)
		tx.v.artifacts[id] = art.Clone()
	}

	for id := range tx.deletions {
		artPath := filepath.Join(artifactsDir, id+".json")
		_ = os.Remove(artPath)
		delete(tx.v.artifacts, id)
	}

	tx.committed = true
	return nil
}

// Rollback cancels all staged mutations.
func (tx *Tx) Rollback() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return nil
	}

	tx.staged = make(map[string]*model.Artifact)
	tx.deletions = make(map[string]bool)
	tx.rolledBack = true
	return nil
}
