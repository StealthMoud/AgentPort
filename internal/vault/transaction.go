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

// FaultHook allows injecting failure for transaction fault testing.
type FaultHook func(phase string) error

// Commit validates all staged mutations and atomically applies them to disk and memory via staging tree.
func (tx *Tx) Commit() error {
	return tx.CommitWithFaultHook(nil)
}

// CommitWithFaultHook executes commit with an optional fault injection hook.
func (tx *Tx) CommitWithFaultHook(hook FaultHook) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return fmt.Errorf("transaction already finished")
	}

	// 1. Validation pass
	for id, art := range tx.staged {
		if err := art.Validate(); err != nil {
			return fmt.Errorf("transaction commit validation failed for %s: %w", id, err)
		}
		if err := security.ValidateArtifactSecurity(art); err != nil {
			return fmt.Errorf("transaction commit security check failed for %s: %w", id, err)
		}
	}

	tx.v.mu.Lock()
	defer tx.v.mu.Unlock()

	if hook != nil {
		if err := hook("pre_staging"); err != nil {
			return fmt.Errorf("injected fault at pre_staging: %w", err)
		}
	}

	stagingDir := filepath.Join(tx.v.cfg.VaultDir, fmt.Sprintf(".staged_%d", time.Now().UnixNano()))
	stagedArtifactsDir := filepath.Join(stagingDir, "artifacts")
	if err := os.MkdirAll(stagedArtifactsDir, 0700); err != nil {
		return fmt.Errorf("failed creating staging directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stagingDir)
	}()

	realArtifactsDir := filepath.Join(tx.v.cfg.VaultDir, "artifacts")
	_ = os.MkdirAll(realArtifactsDir, 0700)

	// Copy existing real artifacts to staging directory
	existingEntries, _ := os.ReadDir(realArtifactsDir)
	for _, entry := range existingEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		srcPath := filepath.Join(realArtifactsDir, entry.Name())
		dstPath := filepath.Join(stagedArtifactsDir, entry.Name())
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("failed reading existing artifact for staging: %w", err)
		}
		if err := os.WriteFile(dstPath, data, 0600); err != nil {
			return fmt.Errorf("failed copying existing artifact to staging: %w", err)
		}
	}

	// Apply staged additions/updates to staging directory
	count := 0
	for id, art := range tx.staged {
		if hook != nil {
			if err := hook("during_write"); err != nil {
				return fmt.Errorf("injected fault during_write: %w", err)
			}
		}
		artPath := filepath.Join(stagedArtifactsDir, id+".json")
		data, err := json.MarshalIndent(art, "", "  ")
		if err != nil {
			return fmt.Errorf("failed marshaling artifact %s: %w", id, err)
		}
		if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
			return fmt.Errorf("failed atomic write for staged artifact %s: %w", id, err)
		}
		count++
	}

	if hook != nil {
		if err := hook("after_writes"); err != nil {
			return fmt.Errorf("injected fault after_writes: %w", err)
		}
	}

	// Apply staged deletions to staging directory
	for id := range tx.deletions {
		if hook != nil {
			if err := hook("during_delete"); err != nil {
				return fmt.Errorf("injected fault during_delete: %w", err)
			}
		}
		artPath := filepath.Join(stagedArtifactsDir, id+".json")
		_ = os.Remove(artPath)
	}

	if hook != nil {
		if err := hook("pre_commit"); err != nil {
			return fmt.Errorf("injected fault pre_commit: %w", err)
		}
	}

	// Commit Pass: Copy verified staging files into real directory via atomic write
	stagedEntries, err := os.ReadDir(stagedArtifactsDir)
	if err != nil {
		return fmt.Errorf("failed reading staging directory: %w", err)
	}

	for _, entry := range stagedEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		stagedFile := filepath.Join(stagedArtifactsDir, entry.Name())
		realFile := filepath.Join(realArtifactsDir, entry.Name())
		data, err := os.ReadFile(stagedFile)
		if err != nil {
			return fmt.Errorf("failed reading staged file: %w", err)
		}
		if err := fsutil.WriteFileAtomic(realFile, data, 0600); err != nil {
			return fmt.Errorf("failed writing real file: %w", err)
		}
	}

	// Remove deleted files from real directory
	for id := range tx.deletions {
		realFile := filepath.Join(realArtifactsDir, id+".json")
		_ = os.Remove(realFile)
	}

	// Update in-memory state ONLY AFTER disk write succeeds completely
	for id, art := range tx.staged {
		tx.v.artifacts[id] = art.Clone()
	}
	for id := range tx.deletions {
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
