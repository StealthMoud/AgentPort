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

func TestSnapshotV2AndMixedState(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// 1. V1 artifact
	v1Art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "V1 Mixed Test Item",
		Content:       "V1 original content",
	}
	_ = v.SaveArtifact(v1Art)

	// 2. V2 envelope
	v2Env := &model.EnvelopeV2{
		ID:            "apm_snap_test_v2",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "V2 original memory statement",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	v2Env.RevisionHash = model.ComputeRevisionHash(v2Env)
	_ = v.SaveEntity(v2Env)

	snapMgr := snapshot.NewManager(cfg)
	snapMeta, err := snapMgr.CreateSnapshot(v, "Mixed V1+V2 state snapshot")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Mutate vault: modify V2 memory, delete V1 artifact, add another V2 memory
	v2EnvMutated := v2Env.Clone()
	v2EnvMutated.Memory.Statement = "MUTATED STATEMENT TO BE RESTORED"
	_ = v.UpdateEntity(v2EnvMutated)
	_ = v.DeleteArtifact(v1Art.ID)

	v2Env2 := &model.EnvelopeV2{
		ID:            "apm_temp_to_wipe",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Should be wiped",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 5,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	v2Env2.RevisionHash = model.ComputeRevisionHash(v2Env2)
	_ = v.SaveEntity(v2Env2)

	// Restore snapshot
	if err := snapMgr.RestoreSnapshot(v, snapMeta.SnapshotID); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	// Verify exact original V1 artifact and V2 envelope state restored
	restoredV1 := v.ListArtifacts()
	if len(restoredV1) != 1 || restoredV1[0].Title != "V1 Mixed Test Item" {
		t.Fatalf("V1 artifact failed to restore correctly!")
	}

	restoredV2 := v.ListEntities()
	if len(restoredV2) != 1 || restoredV2[0].ID != "apm_snap_test_v2" {
		t.Fatalf("V2 entity failed to restore correctly, count=%d", len(restoredV2))
	}
	if restoredV2[0].Memory.Statement != "V2 original memory statement" {
		t.Errorf("expected restored statement 'V2 original memory statement', got %s", restoredV2[0].Memory.Statement)
	}
}
