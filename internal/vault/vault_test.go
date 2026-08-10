package vault_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestVaultInitializationAndArtifactOperations(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "agentport_home")
	vaultDir := filepath.Join(tempDir, "agentport_vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	v, err := vault.Initialize(cfg)
	if err != nil {
		t.Fatalf("vault.Initialize failed: %v", err)
	}

	if v.Metadata.VaultID == "" {
		t.Errorf("expected non-empty VaultID")
	}

	if v.Machine.MachineID == "" {
		t.Errorf("expected non-empty MachineID")
	}

	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Test Memory",
		Content:       "User prefers dark mode and Go 1.26.",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := v.SaveArtifact(art); err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}

	retrieved, exists := v.GetArtifact(art.ID)
	if !exists {
		t.Fatalf("expected artifact to exist in vault")
	}

	if retrieved.Title != art.Title {
		t.Errorf("expected title %s, got %s", art.Title, retrieved.Title)
	}

	validation := v.Validate()
	if !validation.Healthy {
		t.Fatalf("expected healthy vault validation, got errors: %v", validation.Errors)
	}

	if validation.ValidArtifacts != 1 {
		t.Errorf("expected 1 valid artifact, got %d", validation.ValidArtifacts)
	}
}

func TestVaultImmutabilityAndCopySemantics(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "agentport_home")
	vaultDir := filepath.Join(tempDir, "agentport_vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	v, err := vault.Initialize(cfg)
	if err != nil {
		t.Fatalf("vault.Initialize failed: %v", err)
	}

	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Immutable Memory",
		Content:       "Original Content",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
	}

	if err := v.SaveArtifact(art); err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}

	// Retrieve copy and mutate it
	retrieved, exists := v.GetArtifact(art.ID)
	if !exists {
		t.Fatalf("artifact not found")
	}

	retrieved.Content = "Mutated Content"
	retrieved.Title = "Mutated Title"

	// Fetch again from vault
	fresh, _ := v.GetArtifact(art.ID)
	if fresh.Content == "Mutated Content" {
		t.Errorf("vault internal state was mutated via external reference modification")
	}
	if fresh.Content != "Original Content" {
		t.Errorf("expected original content 'Original Content', got '%s'", fresh.Content)
	}
}

func TestVaultTransactionsCommitAndRollback(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "agentport_home")
	vaultDir := filepath.Join(tempDir, "agentport_vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	v, err := vault.Initialize(cfg)
	if err != nil {
		t.Fatalf("vault.Initialize failed: %v", err)
	}

	// 1. Rollback test
	txRoll := v.BeginTx()
	art1 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Staged Memory Rollback",
		Content:       "Should not be saved",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
	}
	if err := txRoll.SaveArtifact(art1); err != nil {
		t.Fatalf("txRoll.SaveArtifact failed: %v", err)
	}
	if err := txRoll.Rollback(); err != nil {
		t.Fatalf("txRoll.Rollback failed: %v", err)
	}

	if _, exists := v.GetArtifact(art1.ID); exists {
		t.Errorf("rolled back artifact should not exist in vault")
	}

	// 2. Commit test
	txCommit := v.BeginTx()
	art2 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Staged Memory Commit",
		Content:       "Should be saved atomically",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
	}
	if err := txCommit.SaveArtifact(art2); err != nil {
		t.Fatalf("txCommit.SaveArtifact failed: %v", err)
	}
	if err := txCommit.Commit(); err != nil {
		t.Fatalf("txCommit.Commit failed: %v", err)
	}

	if _, exists := v.GetArtifact(art2.ID); !exists {
		t.Errorf("committed artifact should exist in vault")
	}
}

func TestVaultTransactionFaultInjection(t *testing.T) {
	faultPhases := []string{"pre_staging", "during_write", "after_writes", "during_delete", "pre_commit"}

	for _, phase := range faultPhases {
		t.Run("FaultAt_"+phase, func(t *testing.T) {
			tempDir := t.TempDir()
			homeDir := filepath.Join(tempDir, "agentport_home")
			vaultDir := filepath.Join(tempDir, "agentport_vault")

			t.Setenv(config.EnvAppHome, homeDir)
			t.Setenv(config.EnvVaultDir, vaultDir)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("config.Load failed: %v", err)
			}

			v, err := vault.Initialize(cfg)
			if err != nil {
				t.Fatalf("vault.Initialize failed: %v", err)
			}

			origArt := &model.Artifact{
				SchemaVersion: model.SchemaVersionV1,
				Kind:          model.KindMemory,
				Scope:         model.ScopeGlobal,
				Title:         "Original Vault Item",
				Content:       "Initial State",
				Sensitivity:   model.SensitivityNormal,
			}
			if err := v.SaveArtifact(origArt); err != nil {
				t.Fatalf("SaveArtifact failed: %v", err)
			}

			tx := v.BeginTx()
			newArt := &model.Artifact{
				SchemaVersion: model.SchemaVersionV1,
				Kind:          model.KindInstruction,
				Scope:         model.ScopeGlobal,
				Title:         "Fault Injected Item",
				Content:       "Should Never Persist",
				Sensitivity:   model.SensitivityNormal,
			}
			_ = tx.SaveArtifact(newArt)
			_ = tx.DeleteArtifact(origArt.ID)

			err = tx.CommitWithFaultHook(func(p string) error {
				if p == phase {
					return fmt.Errorf("injected fault at %s", p)
				}
				return nil
			})

			if err == nil {
				t.Fatalf("expected commit error for injected fault phase %s", phase)
			}

			// Verify original vault state remains 100% untouched
			item, exists := v.GetArtifact(origArt.ID)
			if !exists {
				t.Fatalf("original artifact was deleted despite transaction failure at phase %s", phase)
			}
			if item.Content != "Initial State" {
				t.Fatalf("original artifact content corrupted at phase %s: got %s", phase, item.Content)
			}
			if _, newExists := v.GetArtifact(newArt.ID); newExists {
				t.Fatalf("new artifact persisted despite transaction failure at phase %s", phase)
			}
		})
	}
}

func TestTransactionAtomicFailureDuringFinalSwap(t *testing.T) {
	swapPhases := []string{
		"pre_staging",
		"during_write",
		"after_writes",
		"during_delete",
		"pre_swap",
		"after_backup_rename",
		"during_final_swap",
	}

	for _, phase := range swapPhases {
		t.Run("SwapFault_"+phase, func(t *testing.T) {
			tempDir := t.TempDir()
			homeDir := filepath.Join(tempDir, "home")
			vaultDir := filepath.Join(tempDir, "vault")

			t.Setenv(config.EnvAppHome, homeDir)
			t.Setenv(config.EnvVaultDir, vaultDir)

			cfg, _ := config.Load()
			v, _ := vault.Initialize(cfg)

			origArt := &model.Artifact{
				SchemaVersion: model.SchemaVersionV1,
				Kind:          model.KindMemory,
				Scope:         model.ScopeGlobal,
				Title:         "Original Vault Item",
				Content:       "Initial State",
			}
			_ = v.SaveArtifact(origArt)

			tx := v.BeginTx()
			newArt := &model.Artifact{
				SchemaVersion: model.SchemaVersionV1,
				Kind:          model.KindInstruction,
				Scope:         model.ScopeGlobal,
				Title:         "Atomic Swap Item",
				Content:       "Should Never Persist On Failure",
			}
			_ = tx.SaveArtifact(newArt)
			_ = tx.DeleteArtifact(origArt.ID)

			err := tx.CommitWithFaultHook(func(p string) error {
				if p == phase {
					return fmt.Errorf("injected swap fault at %s", p)
				}
				return nil
			})

			if err == nil {
				t.Fatalf("expected commit error for swap fault phase %s", phase)
			}

			// Reopen vault from disk after simulated fault to verify crash recovery
			reopenedVault, err := vault.LoadOpen(cfg)
			if err != nil {
				t.Fatalf("vault failed to reopen from disk after fault phase %s: %v", phase, err)
			}

			item, exists := reopenedVault.GetArtifact(origArt.ID)
			if !exists || item.Content != "Initial State" {
				t.Fatalf("reopened vault disk state corrupted at swap fault phase %s!", phase)
			}
			if _, newExists := reopenedVault.GetArtifact(newArt.ID); newExists {
				t.Fatalf("new artifact leaked to disk despite transaction failure at phase %s", phase)
			}
		})
	}
}

func TestVaultKeyRecipientCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "agentport_home")
	vaultDir := filepath.Join(tempDir, "agentport_vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	v, err := vault.Initialize(cfg)
	if err != nil {
		t.Fatalf("vault.Initialize failed: %v", err)
	}

	// 1. Correct vault key re-load
	v2, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("expected LoadOpen with correct key to succeed, got: %v", err)
	}
	if v2.Metadata.Recipient != v.Metadata.Recipient {
		t.Errorf("expected matching recipient")
	}

	// 2. Different key attempt
	diffKeyDir := filepath.Join(tempDir, "diff_keys")
	t.Setenv(config.EnvKeysDir, diffKeyDir)

	diffCfg, _ := config.Load()
	_ = diffCfg.EnsureDirectories()
	diffKey, err := crypt.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	_ = crypt.SaveIdentityToFile(diffKey.Identity, filepath.Join(diffKeyDir, "identity.age"))

	_, err = vault.LoadOpen(diffCfg)
	if err == nil {
		t.Fatalf("expected LoadOpen with different key to fail recipient mismatch check")
	}
}
