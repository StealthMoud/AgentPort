package snapshot_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestSnapshotCreateListAndRestore(t *testing.T) {
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

	art1 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Initial Instruction",
		Content:       "Always check unit tests.",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := v.SaveArtifact(art1); err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}

	snapMgr := snapshot.NewManager(cfg)
	snapMeta, err := snapMgr.CreateSnapshot(v, "Initial test snapshot")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	snaps, err := snapMgr.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}

	// Modify vault state by adding a second artifact
	art2 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Temporary Memory",
		Content:       "Will be wiped on restore.",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecycleTemporary,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := v.SaveArtifact(art2); err != nil {
		t.Fatalf("SaveArtifact art2 failed: %v", err)
	}

	if len(v.ListArtifacts()) != 2 {
		t.Fatalf("expected 2 artifacts before restore, got %d", len(v.ListArtifacts()))
	}

	// Restore initial snapshot
	if err := snapMgr.RestoreSnapshot(v, snapMeta.SnapshotID); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	artifactsAfter := v.ListArtifacts()
	if len(artifactsAfter) != 1 {
		t.Fatalf("expected 1 artifact after restore, got %d", len(artifactsAfter))
	}

	if artifactsAfter[0].Title != art1.Title {
		t.Errorf("expected restored title %s, got %s", art1.Title, artifactsAfter[0].Title)
	}
}
