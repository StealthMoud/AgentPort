package gitstore_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestGitStoreSyncLocalEncryptedRepo(t *testing.T) {
	ctx := context.Background()
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

	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Git Store Test Instruction",
		Content:       "Deterministic Git synchronization test content.",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := v.SaveArtifact(art); err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}

	store := gitstore.New(cfg)

	// Dry run test
	dryRes, err := store.Sync(ctx, v, true)
	if err != nil {
		t.Fatalf("Sync dry-run failed: %v", err)
	}
	if dryRes.ObjectsEncryptedCount != 1 {
		t.Errorf("expected 1 object encrypted in dry-run, got %d", dryRes.ObjectsEncryptedCount)
	}

	// Real sync execution
	res, err := store.Sync(ctx, v, false)
	if err != nil {
		t.Fatalf("Sync execution failed: %v", err)
	}
	if res.ObjectsEncryptedCount != 1 {
		t.Errorf("expected 1 object encrypted, got %d", res.ObjectsEncryptedCount)
	}

	// Verify vault validation passes and no plaintext leaked in sync repo
	validation := v.Validate()
	if !validation.Healthy {
		t.Fatalf("vault validation after sync failed: %v", validation.Errors)
	}
}

func TestDryRunFilesystemPurity(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	syncRepoDir := filepath.Join(tempDir, "sync_repo")

	t.Setenv(config.EnvAppHome, tempDir)
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	store := gitstore.New(cfg)
	res, err := store.Sync(ctx, nil, true)
	if err != nil {
		t.Fatalf("dry run sync failed: %v", err)
	}

	if !res.DryRun {
		t.Errorf("expected DryRun=true in result")
	}

	// Verify syncRepoDir was NOT created by dry-run
	if _, err := os.Stat(syncRepoDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run initialized syncRepoDir on disk: %s", syncRepoDir)
	}
}

func TestV2EntityRevisionKeepsID(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_stable_123",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		RevisionHash:  "rev1_hash",
		Memory: &model.MemoryPayload{
			Statement:  "Initial memory statement",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	if err := v.SaveEntity(env); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	// Update entity
	env.Memory.Statement = "Updated memory statement"
	env.RevisionHash = "rev2_hash"
	if err := v.UpdateEntity(env); err != nil {
		t.Fatalf("UpdateEntity failed: %v", err)
	}

	updated, ok := v.GetEntity("apm_stable_123")
	if !ok {
		t.Fatalf("GetEntity failed to find apm_stable_123")
	}

	if updated.ID != "apm_stable_123" {
		t.Errorf("expected stable entity ID 'apm_stable_123', got %s", updated.ID)
	}
	if updated.Revision != 2 {
		t.Errorf("expected Revision=2 after update, got %d", updated.Revision)
	}
	if updated.Memory.Statement != "Updated memory statement" {
		t.Errorf("expected updated statement, got %s", updated.Memory.Statement)
	}
}

func TestV2SyncAcrossTwoIndependentMachines(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Machine A
	homeA := filepath.Join(tempDir, "machine_a_home")
	vaultA := filepath.Join(tempDir, "machine_a_vault")
	t.Setenv(config.EnvAppHome, homeA)
	t.Setenv(config.EnvVaultDir, vaultA)

	cfgA, _ := config.Load()
	vA, _ := vault.Initialize(cfgA)
	vA.Metadata.SchemaVersion = model.SchemaVersionV2

	envA := &model.EnvelopeV2{
		ID:            "apm_sync_v2_999",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		RevisionHash:  "rev1_hash_999",
		Memory: &model.MemoryPayload{
			Statement:  "V2 entity synced across machines",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 9,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	_ = vA.SaveEntity(envA)

	storeA := gitstore.New(cfgA)
	resA, err := storeA.Sync(ctx, vA, false)
	if err != nil || resA.ObjectsEncryptedCount != 1 {
		t.Fatalf("Sync on A failed: %v", err)
	}

	// Machine B
	homeB := filepath.Join(tempDir, "machine_b_home")
	vaultB := filepath.Join(tempDir, "machine_b_vault")
	t.Setenv(config.EnvAppHome, homeB)
	t.Setenv(config.EnvVaultDir, vaultB)

	cfgB, _ := config.Load()
	_ = os.MkdirAll(cfgB.KeysDir, 0700)
	_ = os.MkdirAll(cfgB.VaultDir, 0700)
	keyDataA, _ := os.ReadFile(filepath.Join(cfgA.KeysDir, "identity.age"))
	_ = os.WriteFile(filepath.Join(cfgB.KeysDir, "identity.age"), keyDataA, 0600)
	metaDataA, _ := os.ReadFile(filepath.Join(cfgA.VaultDir, "vault.json"))
	_ = os.WriteFile(filepath.Join(cfgB.VaultDir, "vault.json"), metaDataA, 0600)

	vB, _ := vault.LoadOpen(cfgB)

	// Copy sync repo from A to B (simulating git pull)
	_ = filepath.Walk(cfgA.SyncRepoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(cfgA.SyncRepoDir, path)
		dst := filepath.Join(cfgB.SyncRepoDir, rel)
		_ = os.MkdirAll(filepath.Dir(dst), 0700)
		data, _ := os.ReadFile(path)
		_ = os.WriteFile(dst, data, 0600)
		return nil
	})

	storeB := gitstore.New(cfgB)
	resB, err := storeB.Sync(ctx, vB, false)
	if err != nil {
		t.Fatalf("Sync on B failed: %v", err)
	}
	if resB.ObjectsDecryptedCount != 1 {
		t.Errorf("expected 1 V2 object decrypted on B, got %d", resB.ObjectsDecryptedCount)
	}

	entB, ok := vB.GetEntity("apm_sync_v2_999")
	if !ok {
		t.Fatalf("V2 entity apm_sync_v2_999 not found on Machine B after sync!")
	}
	if entB.Memory.Statement != "V2 entity synced across machines" {
		t.Errorf("content mismatch on Machine B: %s", entB.Memory.Statement)
	}
}
