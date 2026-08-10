package governance_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestV2StateRootChangesAfterSemanticMutation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_stateroot_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Initial state root statement",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	_ = v.SaveEntity(env)

	root1 := model.ComputeV2StateRoot(v.ListEntities())

	// Refine / update entity
	envMutated := env.Clone()
	envMutated.Memory.Statement = "MUTATED state root statement"
	_ = v.UpdateEntity(envMutated)

	root2 := model.ComputeV2StateRoot(v.ListEntities())

	if root1 == root2 {
		t.Fatalf("expected state root to change after semantic mutation, got identical root %s", root1)
	}
}

func TestV2ProposalRejectedAfterEntityMutation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	env := &model.EnvelopeV2{
		ID:            "apm_stale_prop_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Original statement before proposal generation",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	env.RevisionHash = model.ComputeRevisionHash(env)
	_ = v.SaveEntity(env)

	root1 := model.ComputeV2StateRoot(v.ListEntities())

	prop := &compiler.Proposal{
		ID:             "prop_stale_mutation",
		Operation:      compiler.OpRefine,
		TargetIDs:      []string{env.ID},
		ProposedState:  "Proposal statement",
		InputStateRoot: root1,
	}

	// Mutate entity X before applying proposal
	envMutated := env.Clone()
	envMutated.Memory.Statement = "CONCURRENT MUTATION BEFORE APPLY"
	_ = v.UpdateEntity(envMutated)

	// Apply proposal with now stale root1
	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{prop})
	if err == nil {
		t.Fatalf("expected proposal application with stale state root to be rejected, got nil error")
	}
}

func TestGovernanceApplyFailsWhenSnapshotFails(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	prop := &compiler.Proposal{
		ID:            "prop_snap_fail",
		Operation:     compiler.OpCreate,
		ProposedState: "New memory",
	}

	// Break snapshot dir by creating a file where snapshots dir should be
	snapDir := cfg.SnapshotsDir
	_ = os.RemoveAll(snapDir)
	_ = os.WriteFile(snapDir, []byte("NOT A DIRECTORY"), 0600)

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{prop})
	if err == nil {
		t.Fatalf("expected ApplyProposals to FAIL CLOSED when snapshot creation fails, got nil error")
	}

	if len(v.ListEntities()) != 0 {
		t.Fatalf("state was mutated despite snapshot failure!")
	}
}

func TestProposalStoreFailureRestoresCanonicalAndProposalState(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// Save initial proposal in store
	ps := governance.NewProposalStore(cfg)
	prop := &compiler.Proposal{
		ID:            "prop_store_fail_test",
		Operation:     compiler.OpCreate,
		ProposedState: "New memory statement",
		Status:        compiler.ProposalStatusPending,
	}
	if err := ps.SaveProposal(prop); err != nil {
		t.Fatalf("SaveProposal failed: %v", err)
	}

	// Break proposal store by making proposals dir read-only or replacing file with directory
	propFilePath := filepath.Join(vaultDir, "proposals", prop.ID+".json")
	_ = os.Remove(propFilePath)
	_ = os.MkdirAll(propFilePath, 0700) // Replace proposal file with directory to force WriteFileAtomic error

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{prop})
	if err == nil {
		t.Fatalf("expected ApplyProposals to fail when proposal store persistence fails")
	}

	// Reopen vault: canonical state must be clean (0 entities created)
	reopened, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("vault.LoadOpen failed: %v", err)
	}
	if len(reopened.ListEntities()) != 0 {
		t.Errorf("canonical vault state was mutated despite proposal store failure!")
	}

	// Proposal in-memory status must be restored to Pending
	if prop.Status != compiler.ProposalStatusPending {
		t.Errorf("proposal status in memory was left as %s, expected %s", prop.Status, compiler.ProposalStatusPending)
	}
}

func TestAuditFailureRestoresCanonicalAndProposalState(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	ps := governance.NewProposalStore(cfg)
	prop := &compiler.Proposal{
		ID:            "prop_audit_fail_test",
		Operation:     compiler.OpCreate,
		ProposedState: "New memory for audit failure test",
		Status:        compiler.ProposalStatusPending,
	}
	if err := ps.SaveProposal(prop); err != nil {
		t.Fatalf("SaveProposal failed: %v", err)
	}

	// Break audit directory by creating a file named 'audit' in vaultDir
	auditPath := filepath.Join(vaultDir, "audit")
	_ = os.RemoveAll(auditPath)
	_ = os.WriteFile(auditPath, []byte("NOT A DIRECTORY"), 0600)

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{prop})
	if err == nil {
		t.Fatalf("expected ApplyProposals to fail when audit persistence fails")
	}

	// Reopen vault: canonical state must be clean
	reopened, err := vault.LoadOpen(cfg)
	if err != nil {
		t.Fatalf("vault.LoadOpen failed: %v", err)
	}
	if len(reopened.ListEntities()) != 0 {
		t.Errorf("canonical vault state was mutated despite audit persistence failure!")
	}

	// Proposal on disk must be restored to Pending
	_ = os.Remove(auditPath) // remove file block so we can read proposal store
	retrieved, ok := ps.GetProposal(prop.ID)
	if !ok {
		t.Fatalf("proposal missing from proposal store after audit failure rollback")
	}
	if retrieved.Status != compiler.ProposalStatusPending {
		t.Errorf("proposal status on disk was %s, expected %s", retrieved.Status, compiler.ProposalStatusPending)
	}
}

func TestGovernanceRecoveryFailureIsExplicit(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	prop := &compiler.Proposal{
		ID:            "prop_recovery_fail_test",
		Operation:     compiler.OpCreate,
		ProposedState: "Statement causing recovery failure",
		Status:        compiler.ProposalStatusPending,
	}

	// Force proposal persistence to fail
	propFilePath := filepath.Join(vaultDir, "proposals", prop.ID+".json")
	_ = os.MkdirAll(filepath.Dir(propFilePath), 0700)
	_ = os.MkdirAll(propFilePath, 0700)

	// Break snapshot restore by corrupting snapshots dir after snapshot creation
	// We run ApplyProposals in a goroutine or break snapshots dir right before
	// Actually, we can make snapshotsDir a file right after snapshot is created?
	// Or we can corrupt the snapshot file inside snapshotsDir after it's created!
	// A simpler way: make snapshotsDir a read-only directory or corrupt the snapshot metadata file!
	// Let's break the snapshot metadata file right before ApplyProposals or during a hook.
	// Since CreateSnapshot creates a snapshot subfolder in snapshotsDir, if we replace cfg.SnapshotsDir with a file AFTER CreateSnapshot or break permissions, restore will fail.
	// Wait, we can test ErrGovernanceRecoveryFailed by removing the created snapshot directory right before restore.
	// How? Let's break snapshotsDir permissions or replace it!
	// If we replace cfg.SnapshotsDir with a file, CreateSnapshot fails.
	// But if we let CreateSnapshot succeed, then delete snapshotsDir and put a file there, restore fails!

	// Let's test this directly by wrapping proposal store save:
	// If we make `snapshotsDir` a file AFTER tx.Commit(), CreateSnapshot already ran (step 3).
	// But wait! ApplyProposals runs sequentially in single thread:
	// step 3: CreateSnapshot -> creates `snapshots/snap_...`
	// step 4: tx.Commit() -> mutates vault
	// step 5: SaveProposal -> fails (because propFilePath is a dir) -> calls rollbackGovernance
	// inside rollbackGovernance -> RestoreSnapshot tries to read `snapshots/snap_...`
	// If we remove `snapshots` directory before step 5?
	// Wait! We can make propFilePath a dir, AND in a custom test setup we can corrupt the snapshot file!
	// Wait, if we replace `snapshots` directory right before calling ApplyProposals... wait, CreateSnapshot would fail.
	// How to make CreateSnapshot succeed but RestoreSnapshot fail?
	// In Go tests, we can remove the created snapshot subfolder if we know its name? No, snapID is generated dynamically.
	// BUT `snapshotsDir` contains the snapshot subfolders! If we remove `snapshotsDir` completely after snapshot creation?
	// Wait! Can we corrupt `v.cfg.SnapshotsDir` by removing all contents inside `SnapshotsDir` after snapshot is created?
	// No, ApplyProposals runs synchronously.
	// Wait! `v` in memory has `v.cfg`. If we pass a modified `cfg` or if `snapshotsDir` is on a path where `RestoreSnapshot` encounters an unreadable file?
	// If `RestoreSnapshot` cannot find the snapshot ID or if `snapshotsDir/snap_ID/snapshot.json` is missing/corrupt, `RestoreSnapshot` returns `ErrSnapshotNotFound`!
	// So if we delete `snapshots` directory inside `v.cfg.VaultDir`... wait! Can we trigger this by removing `snapshots` directory?
	// Since ApplyProposals is synchronous, how can we remove `snapshots` after `CreateSnapshot` but before `RestoreSnapshot`?
	// We can hook into `v.BeginTx()`! When `BeginTx()` is called, `CreateSnapshot` has ALREADY completed!
	// In `BeginTx()`, we can remove `cfg.SnapshotsDir`!
	// Let's verify:
	// Step 3: snapMgr.CreateSnapshot(v, ...) -> done!
	// Step 4: v.BeginTx() -> called! Here we can remove `cfg.SnapshotsDir` and replace it with a file!
	// Step 4.5: tx.Commit() -> succeeds!
	// Step 5: ps.SaveProposal(prop) -> fails (propFilePath is dir) -> rollbackGovernance -> RestoreSnapshot fails! -> returns ErrGovernanceRecoveryFailed!

	// Let's test this exact hook:
	// Remove snapshots dir right after tx is created, or override!
	// Since `v.BeginTx()` is called during `ApplyProposals`, we can remove `cfg.SnapshotsDir` inside a wrapper or test setup.

	// Let's test:
	_ = os.RemoveAll(cfg.SnapshotsDir)
	_ = os.MkdirAll(cfg.SnapshotsDir, 0700)

	// Watch for CreateSnapshot to finish writing snapshot.json, then delete the snapshot subfolder
	// so that RestoreSnapshot will fail when rollbackGovernance is triggered.
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				entries, err := os.ReadDir(cfg.SnapshotsDir)
				if err == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							metaFile := filepath.Join(cfg.SnapshotsDir, entry.Name(), "snapshot.json")
							if _, statErr := os.Stat(metaFile); statErr == nil {
								// Snapshot creation is 100% complete. Delete the snapshot folder so restore fails.
								_ = os.RemoveAll(filepath.Join(cfg.SnapshotsDir, entry.Name()))
								return
							}
						}
					}
				}
				runtime.Gosched()
			}
		}
	}()

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{prop})
	close(done)

	// Clean up file if created so TempDir cleanup succeeds
	_ = os.RemoveAll(cfg.SnapshotsDir)

	if err == nil {
		t.Fatalf("expected ApplyProposals to fail")
	}

	if !errors.Is(err, governance.ErrGovernanceRecoveryFailed) {
		t.Fatalf("expected error to wrap ErrGovernanceRecoveryFailed, got: %v", err)
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "snapshot") || !strings.Contains(errStr, "failed stage") {
		t.Errorf("expected error message to contain snapshot ID and failed stage, got: %s", errStr)
	}
}

func TestGovernanceProposalDeleteRecoveryFailureIsExplicit(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// Create proposal 1 (not existing on disk prior to apply)
	p1 := &compiler.Proposal{
		ID:            "prop_del_rec_fail_1",
		Operation:     compiler.OpCreate,
		ProposedState: "Memory 1",
		Status:        compiler.ProposalStatusPending,
	}

	// Create proposal 2 whose SaveProposal will fail (triggering rollback)
	p2 := &compiler.Proposal{
		ID:            "prop_del_rec_fail_2",
		Operation:     compiler.OpCreate,
		ProposedState: "Memory 2",
		Status:        compiler.ProposalStatusPending,
	}

	// Make p2 proposal path a directory so SaveProposal(p2) fails
	p2Path := filepath.Join(vaultDir, "proposals", p2.ID+".json")
	_ = os.MkdirAll(p2Path, 0700)

	// Make p1 proposal path a directory containing a file so that DeleteProposal(p1) during rollback fails!
	p1Path := filepath.Join(vaultDir, "proposals", p1.ID+".json")
	_ = os.MkdirAll(filepath.Join(p1Path, "subfolder"), 0700)

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{p1, p2})
	if err == nil {
		t.Fatalf("expected ApplyProposals to fail")
	}

	if !errors.Is(err, governance.ErrGovernanceRecoveryFailed) {
		t.Fatalf("expected error to wrap ErrGovernanceRecoveryFailed when proposal deletion recovery fails, got: %v", err)
	}

	if !strings.Contains(err.Error(), "delete proposal") {
		t.Errorf("expected error message to detail failed proposal deletion operation, got: %v", err)
	}

	// Cleanup directory blocks so test TempDir remove succeeds
	_ = os.RemoveAll(filepath.Join(vaultDir, "proposals"))
}

func TestGovernanceAuditCleanupFailureIsExplicit(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	p1 := &compiler.Proposal{
		ID:            "prop_audit_rec_fail_1",
		Operation:     compiler.OpCreate,
		ProposedState: "Memory 1 for audit rec test",
		Status:        compiler.ProposalStatusPending,
	}
	p2 := &compiler.Proposal{
		ID:            "prop_audit_rec_fail_2",
		Operation:     compiler.OpCreate,
		ProposedState: "Memory 2 for audit rec test",
		Status:        compiler.ProposalStatusPending,
	}

	// p2 proposal file path is a directory -> SaveProposal(p2) will fail after p1 audit event is recorded
	p2Path := filepath.Join(vaultDir, "proposals", p2.ID+".json")
	_ = os.MkdirAll(p2Path, 0700)

	// Watch for audit event file created by p1 and replace it with a non-empty directory so os.Remove(auditFile) fails!
	auditDir := filepath.Join(vaultDir, "audit")
	_ = os.MkdirAll(auditDir, 0700)

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				entries, err := os.ReadDir(auditDir)
				if err == nil {
					for _, entry := range entries {
						if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
							// Audit file recorded! Convert to non-empty dir so os.Remove fails during rollback.
							filePath := filepath.Join(auditDir, entry.Name())
							_ = os.Remove(filePath)
							_ = os.MkdirAll(filepath.Join(filePath, "subfolder"), 0700)
							return
						}
					}
				}
				runtime.Gosched()
			}
		}
	}()

	err := governance.ApplyProposals(v, cfg, []*compiler.Proposal{p1, p2})
	close(done)

	if err == nil {
		t.Fatalf("expected ApplyProposals to fail")
	}

	if !errors.Is(err, governance.ErrGovernanceRecoveryFailed) {
		t.Fatalf("expected error to wrap ErrGovernanceRecoveryFailed when audit cleanup fails, got: %v", err)
	}

	if !strings.Contains(err.Error(), "remove audit record") {
		t.Errorf("expected error message to detail failed audit removal operation, got: %v", err)
	}

	// Cleanup directory blocks so test TempDir remove succeeds
	_ = os.RemoveAll(auditDir)
	_ = os.RemoveAll(filepath.Join(vaultDir, "proposals"))
}
