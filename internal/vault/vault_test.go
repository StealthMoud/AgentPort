package vault_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
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


