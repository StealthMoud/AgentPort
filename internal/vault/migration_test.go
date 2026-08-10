package vault_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestMigrationPersistsV2EntitiesAndReopenPreservesV2(t *testing.T) {
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

	// 1. Create 5 V1 artifacts
	for i := 1; i <= 5; i++ {
		art := &model.Artifact{
			SchemaVersion: model.SchemaVersionV1,
			Kind:          model.KindMemory,
			Scope:         model.ScopeGlobal,
			Title:         fmt.Sprintf("V1 Memory Item %d", i),
			Content:       fmt.Sprintf("Legacy content statement %d.", i),
			CreatedAt:     time.Now(),
		}
		if err := v.SaveArtifact(art); err != nil {
			t.Fatalf("SaveArtifact failed: %v", err)
		}
	}

	artifacts := v.ListArtifacts()
	if len(artifacts) != 5 {
		t.Fatalf("expected 5 V1 artifacts, got %d", len(artifacts))
	}

	// 2. Build migration plan
	plan, err := model.MigrateV1ToV2(artifacts)
	if err != nil {
		t.Fatalf("MigrateV1ToV2 failed: %v", err)
	}
	if len(plan.ConvertedV2) != 5 {
		t.Fatalf("expected 5 V2 converted envelopes, got %d", len(plan.ConvertedV2))
	}

	// 3. Staged transaction migration
	tx := v.BeginTx()
	for _, art := range artifacts {
		_ = tx.DeleteArtifact(art.ID)
	}
	for _, env := range plan.ConvertedV2 {
		if err := tx.SaveEntity(env); err != nil {
			t.Fatalf("tx.SaveEntity failed: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit migration failed: %v", err)
	}

	// 4. Verify reopening vault loads V2 entities
	v2, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("LoadOpen failed: %v", err)
	}

	entities := v2.ListEntities()
	if len(entities) != 5 {
		t.Fatalf("expected 5 V2 entities in reopened vault, got %d", len(entities))
	}
}

func TestMigrationIdempotent(t *testing.T) {
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
		ID:            "art_fixed_id",
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "V1 Fixed Item",
		Content:       "Content string",
	}
	_ = v.SaveArtifact(art)

	plan1, err := model.MigrateV1ToV2(v.ListArtifacts())
	if err != nil {
		t.Fatalf("plan1 failed: %v", err)
	}

	plan2, err := model.MigrateV1ToV2(v.ListArtifacts())
	if err != nil {
		t.Fatalf("plan2 failed: %v", err)
	}

	if plan1.ConvertedV2[0].ID != plan2.ConvertedV2[0].ID {
		t.Errorf("migration output not idempotent! Got ID %s vs %s", plan1.ConvertedV2[0].ID, plan2.ConvertedV2[0].ID)
	}
}

func TestMigrationFailurePreservesV1(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Pre-failure Memory",
		Content:       "Original V1 content",
	}
	_ = v.SaveArtifact(art)

	// Create snapshot
	snapMgr := snapshot.NewManager(cfg)
	snap, err := snapMgr.CreateSnapshot(v, "pre_failed_migration")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Simulate migration failure: corrupt envelope validation
	corruptEnv := &model.EnvelopeV2{
		ID:            "invalid_env",
		SchemaVersion: "unknown",
	}

	tx := v.BeginTx()
	_ = tx.DeleteArtifact(art.ID)
	err = tx.SaveEntity(corruptEnv)
	if err == nil {
		t.Fatalf("expected SaveEntity with corrupt envelope to fail")
	}

	_ = tx.Rollback()
	_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)

	vReopened, _ := vault.LoadOpen(cfg)
	artifacts := vReopened.ListArtifacts()
	if len(artifacts) != 1 || artifacts[0].Content != "Original V1 content" {
		t.Fatalf("V1 state was lost during failed migration attempt!")
	}
}

func TestMigrationRollback(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// 1. Initial V1 artifact
	origArt := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Rollback Test Memory",
		Content:       "Memory content to be preserved across roundtrip migration.",
		CreatedAt:     time.Now(),
	}
	_ = v.SaveArtifact(origArt)

	// 2. Migrate V1 -> V2
	plan, err := model.MigrateV1ToV2(v.ListArtifacts())
	if err != nil {
		t.Fatalf("MigrateV1ToV2 failed: %v", err)
	}

	tx := v.BeginTx()
	_ = tx.DeleteArtifact(origArt.ID)
	for _, env := range plan.ConvertedV2 {
		_ = tx.SaveEntity(env)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("V1 -> V2 migration transaction failed: %v", err)
	}

	v2Entities := v.ListEntities()
	if len(v2Entities) == 0 {
		t.Fatalf("expected V2 entities after migration")
	}

	v2StateRoot := model.ComputeV2StateRoot(v2Entities)
	if v2StateRoot == "" {
		t.Errorf("expected non-empty V2 state root")
	}

	// 3. Rollback V2 -> V1
	v1Converted := make([]*model.Artifact, 0)
	for _, env := range v2Entities {
		if env.Kind == model.KindSourceRecord {
			continue
		}
		art := &model.Artifact{
			SchemaVersion: model.SchemaVersionV1,
			Kind:          model.KindMemory,
			Scope:         env.Scope,
			Title:         "Rollback Test Memory",
			Content:       env.Memory.Statement,
			ContentType:   "text/plain",
			Lifecycle:     model.LifecyclePersistent,
			Sensitivity:   env.Sensitivity,
			CreatedAt:     env.CreatedAt,
			UpdatedAt:     env.UpdatedAt,
		}
		art.UpdateFingerprint()
		art.ID = model.GenerateArtifactID(art.Kind, art.Fingerprint)
		v1Converted = append(v1Converted, art)
	}

	txRollback := v.BeginTx()
	for _, env := range v2Entities {
		_ = txRollback.DeleteEntity(env.ID)
	}
	for _, art := range v1Converted {
		_ = txRollback.SaveArtifact(art)
	}
	if err := txRollback.Commit(); err != nil {
		t.Fatalf("V2 -> V1 rollback transaction failed: %v", err)
	}

	// 4. Verify original V1 content restored
	restoredArtifacts := v.ListArtifacts()
	if len(restoredArtifacts) != 1 {
		t.Fatalf("expected 1 restored V1 artifact, got %d", len(restoredArtifacts))
	}
	if restoredArtifacts[0].Content != origArt.Content {
		t.Errorf("content lost during roundtrip migration/rollback! expected %q, got %q", origArt.Content, restoredArtifacts[0].Content)
	}
}
