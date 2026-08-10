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
