package reconcile_test

import (
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/reconcile"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func setupTestVault(t *testing.T) (*vault.Vault, *config.Config) {
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

	return v, cfg
}

func TestImportFirstObservationCreatesRevision1(t *testing.T) {
	v, _ := setupTestVault(t)

	imported := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Initial instruction content.",
				SourceHash:       "hash_v1",
			},
		},
	}

	res, err := reconcile.ReconcileV2(v, imported)
	if err != nil {
		t.Fatalf("ReconcileV2 failed: %v", err)
	}

	if len(res.Created) != 1 {
		t.Fatalf("expected 1 created envelope, got %d", len(res.Created))
	}
	if len(res.Updated) != 0 || len(res.Unchanged) != 0 {
		t.Errorf("expected 0 updated and 0 unchanged envelopes")
	}

	created := res.Created[0]
	if created.Revision != 1 {
		t.Errorf("expected Revision == 1, got %d", created.Revision)
	}
	if created.RevisionHash == "" {
		t.Errorf("expected non-empty RevisionHash")
	}
	if created.ID == "" {
		t.Errorf("expected generated ID")
	}
}

func TestImportUnchangedIsNoOp(t *testing.T) {
	v, _ := setupTestVault(t)

	imported := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Same instruction content.",
				SourceHash:       "hash_v1",
			},
		},
	}

	res1, _ := reconcile.ReconcileV2(v, imported)
	if err := v.SaveEntity(res1.Created[0]); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	// Re-import identical content
	res2, err := reconcile.ReconcileV2(v, imported)
	if err != nil {
		t.Fatalf("second ReconcileV2 failed: %v", err)
	}

	if len(res2.Unchanged) != 1 {
		t.Fatalf("expected 1 unchanged envelope, got %d", len(res2.Unchanged))
	}
	if len(res2.Created) != 0 || len(res2.Updated) != 0 {
		t.Errorf("expected 0 created and 0 updated envelopes on unchanged re-import")
	}

	unchanged := res2.Unchanged[0]
	if unchanged.ID != res1.Created[0].ID {
		t.Errorf("expected same ID %s, got %s", res1.Created[0].ID, unchanged.ID)
	}
	if unchanged.Revision != 1 {
		t.Errorf("expected Revision to remain 1, got %d", unchanged.Revision)
	}
	if unchanged.RevisionHash != res1.Created[0].RevisionHash {
		t.Errorf("expected exact same RevisionHash, got %s vs %s", res1.Created[0].RevisionHash, unchanged.RevisionHash)
	}
}

func TestImportChangedIncrementsRevision(t *testing.T) {
	v, _ := setupTestVault(t)

	imp1 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Initial instruction content.",
				SourceHash:       "hash_v1",
			},
		},
	}

	res1, _ := reconcile.ReconcileV2(v, imp1)
	if err := v.SaveEntity(res1.Created[0]); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	// Import modified content
	imp2 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "MODIFIED instruction content!",
				SourceHash:       "hash_v2",
			},
		},
	}

	res2, err := reconcile.ReconcileV2(v, imp2)
	if err != nil {
		t.Fatalf("ReconcileV2 on changed input failed: %v", err)
	}

	if len(res2.Updated) != 1 {
		t.Fatalf("expected 1 updated envelope, got %d", len(res2.Updated))
	}

	updated := res2.Updated[0]
	if updated.Revision != 2 {
		t.Errorf("expected Revision == 2, got %d", updated.Revision)
	}
	if updated.RevisionHash == res1.Created[0].RevisionHash {
		t.Errorf("expected new RevisionHash for modified content")
	}
}

func TestImportChangedKeepsLogicalID(t *testing.T) {
	v, _ := setupTestVault(t)

	imp1 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Version 1 content.",
				SourceHash:       "hash_1",
			},
		},
	}

	res1, _ := reconcile.ReconcileV2(v, imp1)
	initialID := res1.Created[0].ID
	if err := v.SaveEntity(res1.Created[0]); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	imp2 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Version 2 modified content.",
				SourceHash:       "hash_2",
			},
		},
	}

	res2, _ := reconcile.ReconcileV2(v, imp2)
	if len(res2.Updated) != 1 {
		t.Fatalf("expected 1 updated envelope, got %d", len(res2.Updated))
	}

	if res2.Updated[0].ID != initialID {
		t.Errorf("logical entity ID changed across updates: expected %s, got %s", initialID, res2.Updated[0].ID)
	}
}

func TestSourceRecordPreviousRevision(t *testing.T) {
	v, _ := setupTestVault(t)

	imp1 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Initial text",
				SourceHash:       "source_hash_alpha",
			},
		},
	}

	res1, _ := reconcile.ReconcileV2(v, imp1)
	if err := v.SaveEntity(res1.Created[0]); err != nil {
		t.Fatalf("SaveEntity failed: %v", err)
	}

	imp2 := []*model.EnvelopeV2{
		{
			Kind:  model.KindSourceRecord,
			Scope: model.ScopeGlobal,
			SourceRecord: &model.SourceRecord{
				Provider:         "codex",
				MachineID:        "apm_machine1",
				LogicalSourceKey: "instructions.md",
				Content:          "Updated text",
				SourceHash:       "source_hash_beta",
			},
		},
	}

	res2, _ := reconcile.ReconcileV2(v, imp2)
	if len(res2.Updated) != 1 || res2.Updated[0].SourceRecord == nil {
		t.Fatalf("expected updated envelope with SourceRecord")
	}

	prevRev := res2.Updated[0].SourceRecord.PreviousRevision
	if prevRev != "source_hash_alpha" && prevRev != res1.Created[0].RevisionHash {
		t.Errorf("expected PreviousRevision to reference previous source hash or revision hash, got %s", prevRev)
	}
}
