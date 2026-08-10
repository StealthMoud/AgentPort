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

func TestGovernanceProposalOperations(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	mem1 := &model.EnvelopeV2{
		ID:            "apm_mem1",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Statement 1",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	mem1.RevisionHash = model.ComputeRevisionHash(mem1)
	_ = v.SaveEntity(mem1)

	mem2 := &model.EnvelopeV2{
		ID:            "apm_mem2",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Statement 2",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	mem2.RevisionHash = model.ComputeRevisionHash(mem2)
	_ = v.SaveEntity(mem2)

	stateRoot := model.ComputeV2StateRoot(v.ListEntities())

	// 1. Create Proposal
	pCreate := &compiler.Proposal{
		ID:             "prop_create",
		Operation:      compiler.OpCreate,
		ProposedState:  "Brand new created memory",
		Confidence:     0.9,
		InputStateRoot: stateRoot,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pCreate}); err != nil {
		t.Fatalf("OpCreate failed: %v", err)
	}

	stateRoot2 := model.ComputeV2StateRoot(v.ListEntities())

	// 2. Merge Proposal (Merge mem1 and mem2)
	pMerge := &compiler.Proposal{
		ID:             "prop_merge",
		Operation:      compiler.OpMerge,
		TargetIDs:      []string{"apm_mem1", "apm_mem2"},
		ProposedState:  "Merged Statement 1 & 2",
		Confidence:     0.95,
		InputStateRoot: stateRoot2,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pMerge}); err != nil {
		t.Fatalf("OpMerge failed: %v", err)
	}

	// Verify mem1 and mem2 marked MemoryStatusSuperseded (not deleted)
	m1, _ := v.GetEntity("apm_mem1")
	if m1.Memory.Status != model.MemoryStatusSuperseded {
		t.Errorf("expected mem1 status MemoryStatusSuperseded, got %s", m1.Memory.Status)
	}

	stateRoot3 := model.ComputeV2StateRoot(v.ListEntities())

	// 3. Refine Proposal on mem1
	pRefine := &compiler.Proposal{
		ID:             "prop_refine",
		Operation:      compiler.OpRefine,
		TargetIDs:      []string{"apm_mem1"},
		ProposedState:  "Refined Statement 1",
		Confidence:     0.9,
		InputStateRoot: stateRoot3,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pRefine}); err != nil {
		t.Fatalf("OpRefine failed: %v", err)
	}
	m1Refined, _ := v.GetEntity("apm_mem1")
	if m1Refined.Memory.Statement != "Refined Statement 1" {
		t.Errorf("expected refined statement 'Refined Statement 1', got %s", m1Refined.Memory.Statement)
	}

	stateRoot4 := model.ComputeV2StateRoot(v.ListEntities())

	// 4. Archive Proposal on mem2
	pArchive := &compiler.Proposal{
		ID:             "prop_archive",
		Operation:      compiler.OpArchive,
		TargetIDs:      []string{"apm_mem2"},
		Confidence:     0.9,
		InputStateRoot: stateRoot4,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pArchive}); err != nil {
		t.Fatalf("OpArchive failed: %v", err)
	}
	m2Archived, _ := v.GetEntity("apm_mem2")
	if m2Archived.Memory.Status != model.MemoryStatusArchived {
		t.Errorf("expected status MemoryStatusArchived, got %s", m2Archived.Memory.Status)
	}

	stateRoot5 := model.ComputeV2StateRoot(v.ListEntities())

	// 5. Mark Conflict Proposal
	pConflict := &compiler.Proposal{
		ID:             "prop_conflict",
		Operation:      compiler.OpMarkConflict,
		TargetIDs:      []string{"apm_mem1"},
		Confidence:     0.9,
		InputStateRoot: stateRoot5,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pConflict}); err != nil {
		t.Fatalf("OpMarkConflict failed: %v", err)
	}
	m1Conflict, _ := v.GetEntity("apm_mem1")
	if m1Conflict.Memory.Status != model.MemoryStatusContested {
		t.Errorf("expected status MemoryStatusContested, got %s", m1Conflict.Memory.Status)
	}

	stateRoot6 := model.ComputeV2StateRoot(v.ListEntities())

	// 6. Mark Stale Proposal
	pStale := &compiler.Proposal{
		ID:             "prop_stale",
		Operation:      compiler.OpMarkStale,
		TargetIDs:      []string{"apm_mem1"},
		Confidence:     0.9,
		InputStateRoot: stateRoot6,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pStale}); err != nil {
		t.Fatalf("OpMarkStale failed: %v", err)
	}
	m1Stale, _ := v.GetEntity("apm_mem1")
	if m1Stale.Memory.Status != model.MemoryStatusExpired {
		t.Errorf("expected status MemoryStatusExpired, got %s", m1Stale.Memory.Status)
	}

	stateRoot7 := model.ComputeV2StateRoot(v.ListEntities())

	// 7. Reclassify Proposal
	pReclass := &compiler.Proposal{
		ID:             "prop_reclass",
		Operation:      compiler.OpReclassify,
		TargetIDs:      []string{"apm_mem1"},
		ProposedState:  string(model.CategoryDecision),
		Confidence:     0.9,
		InputStateRoot: stateRoot7,
	}
	if err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{pReclass}); err != nil {
		t.Fatalf("OpReclassify failed: %v", err)
	}
	m1Reclass, _ := v.GetEntity("apm_mem1")
	if m1Reclass.Memory.Category != model.CategoryDecision {
		t.Errorf("expected category CategoryDecision, got %s", m1Reclass.Memory.Category)
	}
}

func TestGovernanceStateRootValidation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	staleProp := &compiler.Proposal{
		ID:             "prop_stale_root",
		Operation:      compiler.OpCreate,
		ProposedState:  "State statement",
		InputStateRoot: "STALE_EXPECTED_ROOT_HASH_9999",
	}

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{staleProp})
	if err == nil {
		t.Fatalf("expected governance.ApplyProposals to reject proposal with stale state root")
	}
}
