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
