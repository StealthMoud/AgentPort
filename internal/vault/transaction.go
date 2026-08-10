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
	mu             sync.Mutex
	v              *Vault
	staged         map[string]*model.Artifact
	stagedEntities map[string]*model.EnvelopeV2
	deletions      map[string]bool
	committed      bool
	rolledBack     bool
}

// BeginTx starts a new transaction against the vault.
func (v *Vault) BeginTx() *Tx {
	return &Tx{
		v:              v,
		staged:         make(map[string]*model.Artifact),
		stagedEntities: make(map[string]*model.EnvelopeV2),
		deletions:      make(map[string]bool),
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

// SaveEntity stages a Schema V2 Envelope write in the transaction.
func (tx *Tx) SaveEntity(env *model.EnvelopeV2) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledBack {
		return fmt.Errorf("transaction already finished")
	}

	if env.SchemaVersion == "" {
		env.SchemaVersion = model.SchemaVersionV2
	}
	if env.Revision < 1 {
		env.Revision = 1
	}

	if err := env.Validate(); err != nil {
		return err
	}

	if err := security.ValidateEnvelopeSecurity(env); err != nil {
		return err
	}

	if env.CreatedAt.IsZero() {
		env.CreatedAt = time.Now()
	}
	env.UpdatedAt = time.Now()

	tx.stagedEntities[env.ID] = env
	delete(tx.deletions, env.ID)
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
	delete(tx.stagedEntities, id)
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
	for id, env := range tx.stagedEntities {
		if err := env.Validate(); err != nil {
			return fmt.Errorf("transaction commit entity validation failed for %s: %w", id, err)
		}
		if err := security.ValidateEnvelopeSecurity(env); err != nil {
			return fmt.Errorf("transaction commit entity security check failed for %s: %w", id, err)
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

	// Copy existing real artifacts/entities to staging directory
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

	if hook != nil {
		if err := hook("during_staging"); err != nil {
			return fmt.Errorf("injected fault during_staging: %w", err)
		}
	}

	// Apply staged V1 additions/updates to staging directory
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
	}

	// Apply staged V2 additions/updates to staging directory
	for id, env := range tx.stagedEntities {
		if hook != nil {
			if err := hook("during_write"); err != nil {
				return fmt.Errorf("injected fault during_write: %w", err)
			}
		}
		envPath := filepath.Join(stagedArtifactsDir, id+".json")
		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return fmt.Errorf("failed marshaling entity %s: %w", id, err)
		}
		if err := fsutil.WriteFileAtomic(envPath, data, 0600); err != nil {
			return fmt.Errorf("failed atomic write for staged entity %s: %w", id, err)
		}
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
		if err := hook("pre_swap"); err != nil {
			return fmt.Errorf("injected fault pre_swap: %w", err)
		}
	}

	// Whole-directory atomic swap: rename realArtifactsDir -> backupDir, move stagedArtifactsDir -> realArtifactsDir
	backupDir := filepath.Join(tx.v.cfg.VaultDir, fmt.Sprintf("artifacts_backup_%d", time.Now().UnixNano()))

	if err := os.Rename(realArtifactsDir, backupDir); err != nil {
		_, _ = fsutil.BackupFile(realArtifactsDir, backupDir)
	}

	if hook != nil {
		if err := hook("after_backup_rename"); err != nil {
			_ = os.Rename(backupDir, realArtifactsDir)
			return fmt.Errorf("injected fault after_backup_rename: %w", err)
		}
	}

	if err := os.Rename(stagedArtifactsDir, realArtifactsDir); err != nil {
		_ = os.Rename(backupDir, realArtifactsDir)
		return fmt.Errorf("failed atomic directory swap: %w", err)
	}

	if hook != nil {
		if err := hook("during_final_swap"); err != nil {
			_ = os.Rename(realArtifactsDir, stagedArtifactsDir)
			_ = os.Rename(backupDir, realArtifactsDir)
			return fmt.Errorf("injected fault during_final_swap: %w", err)
		}
	}

	_ = os.RemoveAll(backupDir)

	if hook != nil {
		if err := hook("post_swap_pre_inmemory"); err != nil {
			return fmt.Errorf("injected fault post_swap_pre_inmemory: %w", err)
		}
	}

	// Update in-memory state ONLY AFTER atomic directory swap succeeds completely
	for id, art := range tx.staged {
		tx.v.artifacts[id] = art.Clone()
	}
	for id, env := range tx.stagedEntities {
		tx.v.entities[id] = env
	}
	for id := range tx.deletions {
		delete(tx.v.artifacts, id)
		delete(tx.v.entities, id)
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
	tx.stagedEntities = make(map[string]*model.EnvelopeV2)
	tx.deletions = make(map[string]bool)
	tx.rolledBack = true
	return nil
}
