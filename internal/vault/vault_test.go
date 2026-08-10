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

func TestFreshVaultInitializesAsV2(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

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

	if v.Metadata.SchemaVersion != model.SchemaVersionV2 {
		t.Errorf("expected Metadata.SchemaVersion == %s, got %s", model.SchemaVersionV2, v.Metadata.SchemaVersion)
	}

	if v.Metadata.FormatVersion != "2" {
		t.Errorf("expected Metadata.FormatVersion == '2', got %s", v.Metadata.FormatVersion)
	}

	if len(v.ListArtifacts()) != 0 {
		t.Errorf("expected 0 legacy artifacts in fresh V2 vault, got %d", len(v.ListArtifacts()))
	}

	env := &model.EnvelopeV2{
		ID:            "apm_fresh_v2_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Fresh V2 test statement",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	if err := v.SaveEntity(env); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	entities := v.ListEntities()
	if len(entities) != 1 {
		t.Fatalf("expected 1 V2 entity after SaveEntity, got %d", len(entities))
	}
}

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

func TestVaultV2Immutability(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            model.GenerateEntityID("apm"),
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Immutability Test Statement",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)

	// 1. Input immutability
	if err := v.SaveEntity(env); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}
	env.Memory.Statement = "MUTATED STATEMENT OUTSIDE VAULT"

	retrieved, ok := v.GetEntity(env.ID)
	if !ok {
		t.Fatalf("GetEntity failed")
	}
	if retrieved.Memory.Statement != "Immutability Test Statement" {
		t.Errorf("vault internal state mutated by external input struct mutation! got: %s", retrieved.Memory.Statement)
	}

	// 2. Output immutability
	retrieved.Memory.Statement = "MUTATED OUTPUT STRUCT"
	retrieved2, _ := v.GetEntity(env.ID)
	if retrieved2.Memory.Statement != "Immutability Test Statement" {
		t.Errorf("vault internal state mutated by external output struct mutation! got: %s", retrieved2.Memory.Statement)
	}

	// 3. Slice immutability
	entities := v.ListEntities()
	entities[0].Memory.Statement = "MUTATED SLICE ELEMENT"
	retrieved3, _ := v.GetEntity(env.ID)
	if retrieved3.Memory.Statement != "Immutability Test Statement" {
		t.Errorf("vault internal state mutated by ListEntities slice mutation!")
	}
}

func TestTombstoneLoopPrevention(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_tombstone_test_123",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "To be soft-deleted by remote tombstone",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	_ = v.SaveEntity(env)

	remoteTS := &model.Tombstone{
		EntityID:             env.ID,
		PreviousRevisionHash: env.RevisionHash,
		DeletedAt:            time.Now(),
	}

	// Apply remote tombstone locally once
	if err := v.ApplyRemoteTombstone(remoteTS); err != nil {
		t.Fatalf("ApplyRemoteTombstone failed: %v", err)
	}

	// Verify entity is removed locally
	if _, exists := v.GetEntity(env.ID); exists {
		t.Errorf("expected entity to be deleted after applying remote tombstone")
	}

	t1, _ := v.ListTombstones()
	firstCount := len(t1)

	// Re-applying the exact same remote tombstone must be idempotent and not create duplicate tombstones
	if err := v.ApplyRemoteTombstone(remoteTS); err != nil {
		t.Fatalf("second ApplyRemoteTombstone failed: %v", err)
	}

	t2, _ := v.ListTombstones()
	secondCount := len(t2)
	if secondCount != firstCount {
		t.Errorf("expected tombstone list length unchanged on re-applying remote tombstone (%d), got %d (infinite tombstone loop!)", firstCount, secondCount)
	}
}

func TestFailedDeleteTransactionDoesNotLeaveTombstone(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_tx_fail_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Should survive failed transaction deletion",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	_ = v.SaveEntity(env)

	tx := v.BeginTx()
	_ = tx.DeleteEntity(env.ID)

	// Commit with fault hook returning an error before atomic swap
	err := tx.CommitWithFaultHook(func(phase string) error {
		if phase == "pre_swap" {
			return fmt.Errorf("injected pre_swap failure")
		}
		return nil
	})

	if err == nil {
		t.Fatalf("expected commit to fail due to fault hook")
	}

	// Reopen vault from disk
	reopened, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("vault.LoadOpen failed: %v", err)
	}

	// Assert entity still exists and NO tombstone was created
	if _, exists := reopened.GetEntity(env.ID); !exists {
		t.Errorf("expected entity to still exist on disk after failed transaction deletion!")
	}

	if _, tombExists := reopened.GetTombstone(env.ID); tombExists {
		t.Errorf("failed delete transaction leaked orphaned tombstone to disk!")
	}
}

// TestTombstoneSwapRollbackOnFault verifies that if the tombstone directory swap fails
// after artifacts have already been swapped, both directories are rolled back atomically.
func TestTombstoneSwapRollbackOnFault(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_tombswap_rollback_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Tombstone swap rollback test",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 7,
			Confidence: 0.9,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	_ = v.SaveEntity(env)

	// Record original state root
	root1 := model.ComputeV2StateRoot(v.ListEntities())

	// Attempt a delete that will fail at the tombstones rename stage
	tx := v.BeginTx()
	_ = tx.DeleteEntity(env.ID)

	err := tx.CommitWithFaultHook(func(phase string) error {
		if phase == "during_final_swap" {
			return fmt.Errorf("injected fault during_final_swap")
		}
		return nil
	})

	if err == nil {
		t.Fatalf("expected commit to fail at during_final_swap hook")
	}

	// Both artifact and tombstone dirs must have been rolled back: entity must still exist.
	reopened, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("vault.LoadOpen failed: %v", err)
	}

	if _, exists := reopened.GetEntity(env.ID); !exists {
		t.Errorf("entity must survive tombstone swap rollback — disk inconsistency detected")
	}
	if _, tombExists := reopened.GetTombstone(env.ID); tombExists {
		t.Errorf("tombstone must not exist after rollback of failed swap")
	}

	// State root must be identical to before the failed operation
	root2 := model.ComputeV2StateRoot(reopened.ListEntities())
	if root1 != root2 {
		t.Errorf("state root changed after failed tombstone swap rollback: before=%s after=%s", root1, root2)
	}
}

// TestTombstoneSwapRollbackDoesNotCorruptOngoingEntities verifies that a failed deletion
// transaction does not corrupt unrelated entities that were already in the vault.
func TestTombstoneSwapRollbackDoesNotCorruptOngoingEntities(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	makeEntity := func(id, statement string) *model.EnvelopeV2 {
		e := &model.EnvelopeV2{
			ID:            id,
			SchemaVersion: model.SchemaVersionV2,
			Kind:          model.KindMemoryV2,
			Scope:         model.ScopeGlobal,
			Revision:      1,
			Memory: &model.MemoryPayload{
				Statement:  statement,
				Category:   model.CategoryWorkflow,
				Status:     model.MemoryStatusActive,
				Importance: 5,
				Confidence: 0.8,
				Derivation: model.DerivationDirect,
			},
		}
		e.RevisionHash = model.ComputeRevisionHash(e)
		return e
	}

	e1 := makeEntity("apm_survivor", "Survivor entity")
	e2 := makeEntity("apm_target_del", "Entity to delete")
	_ = v.SaveEntity(e1)
	_ = v.SaveEntity(e2)

	// Fail mid-swap while deleting e2
	tx := v.BeginTx()
	_ = tx.DeleteEntity(e2.ID)
	_ = tx.CommitWithFaultHook(func(phase string) error {
		if phase == "after_backup_rename" {
			return fmt.Errorf("injected after_backup_rename fault")
		}
		return nil
	})

	// Both entities must be intact on disk
	reopened, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("vault.LoadOpen failed: %v", err)
	}

	if _, ok := reopened.GetEntity(e1.ID); !ok {
		t.Errorf("survivor entity must still exist after failed delete tx")
	}
	if _, ok := reopened.GetEntity(e2.ID); !ok {
		t.Errorf("target entity must still exist after failed delete tx (not yet committed)")
	}
}
