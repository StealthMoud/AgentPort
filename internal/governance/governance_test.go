package governance_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/governance"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestAuditJournalAndProposalStore(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	// 1. Audit Journal Test
	journal := governance.NewJournal(cfg)
	evt := &governance.AuditEvent{
		Actor:     "test_actor",
		Operation: "TEST_OP",
		TargetID:  "apm_test_target",
	}

	if err := journal.RecordEvent(evt); err != nil {
		t.Fatalf("RecordEvent failed: %v", err)
	}

	events, err := journal.ListEvents()
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].TargetID != "apm_test_target" {
		t.Errorf("expected TargetID 'apm_test_target', got %s", events[0].TargetID)
	}

	// 2. Proposal Store Test
	ps := governance.NewProposalStore(cfg)
	prop := &compiler.Proposal{
		ID:             "prop_test_123",
		ProposalSetID:  "propset_123",
		Operation:      compiler.OpMerge,
		TargetIDs:      []string{"apm_1", "apm_2"},
		ProposedState:  "Merged preference state",
		Confidence:     0.95,
		CreatedAt:      time.Now(),
		Status:         compiler.ProposalStatusPending,
		InputStateRoot: "stateroot_hash",
	}

	if err := ps.SaveProposal(prop); err != nil {
		t.Fatalf("SaveProposal failed: %v", err)
	}

	retrieved, ok := ps.GetProposal("prop_test_123")
	if !ok {
		t.Fatalf("GetProposal failed to find prop_test_123")
	}
	if retrieved.ProposedState != "Merged preference state" {
		t.Errorf("expected ProposedState 'Merged preference state', got %s", retrieved.ProposedState)
	}

	allProps, err := ps.ListProposals()
	if err != nil || len(allProps) != 1 {
		t.Fatalf("ListProposals expected 1 item, got %d (err: %v)", len(allProps), err)
	}
}

func TestProposalUndoRestoresState(t *testing.T) {
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
		Title:         "Pre-Proposal Memory",
		Content:       "Original State Before Proposal",
	}
	_ = v.SaveArtifact(origArt)

	// Create snapshot
	snapMgr := snapshot.NewManager(cfg)
	snap, err := snapMgr.CreateSnapshot(v, "pre_apply")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Mutate state (simulating proposal application)
	_ = v.DeleteArtifact(origArt.ID)
	newArt := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "Applied Memory",
		Content:       "Mutated State After Proposal",
	}
	_ = v.SaveArtifact(newArt)

	// Perform Undo restoring snapshot
	if err := snapMgr.RestoreSnapshot(v, snap.SnapshotID); err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	reopened, _ := vault.LoadOpen(cfg)
	item, ok := reopened.GetArtifact(origArt.ID)
	if !ok || item.Content != "Original State Before Proposal" {
		t.Fatalf("undo failed to restore original state!")
	}
}
