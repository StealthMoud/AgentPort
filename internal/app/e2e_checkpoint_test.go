package app_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/config"
	contextpkg "github.com/StealthMoud/AgentPort/internal/context"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/governance"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestMasterEndToEndCorrectiveCheckpoint(t *testing.T) {
	ctx := context.Background()
	testDir := t.TempDir()

	// Setup shared bare git remote repository
	remoteGitDir := filepath.Join(testDir, "remote.git")
	if err := os.MkdirAll(remoteGitDir, 0700); err != nil {
		t.Fatalf("failed creating remote.git dir: %v", err)
	}

	// 1. Setup Computer A
	compADir := filepath.Join(testDir, "machine_a")
	homeA := filepath.Join(compADir, "home")
	vaultA := filepath.Join(compADir, "vault")
	codexRootA := filepath.Join(compADir, "codex")
	claudeRootA := filepath.Join(compADir, "claude")

	_ = os.MkdirAll(codexRootA, 0700)
	_ = os.MkdirAll(claudeRootA, 0700)

	// Create Codex fixtures on A (AGENTS.md, instructions, skill, agent, safe MCP)
	_ = os.WriteFile(filepath.Join(codexRootA, "AGENTS.md"), []byte("Global Agents Instruction for A."), 0600)
	_ = os.WriteFile(filepath.Join(codexRootA, "instructions.md"), []byte("System instructions for A."), 0600)
	_ = os.MkdirAll(filepath.Join(codexRootA, "skills", "test_skill"), 0700)
	_ = os.WriteFile(filepath.Join(codexRootA, "skills", "test_skill", "SKILL.md"), []byte("Skill definition for A."), 0600)

	t.Setenv(config.EnvAppHome, homeA)
	t.Setenv(config.EnvVaultDir, vaultA)

	cfgA, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load A failed: %v", err)
	}

	vA, err := vault.Initialize(cfgA)
	if err != nil {
		t.Fatalf("vault.Initialize A failed: %v", err)
	}

	// Machine A: Import from Codex
	codexAdA := codex.New(codexRootA)
	envsA, err := codexAdA.ImportV2(ctx, vA.Machine.MachineID, nil)
	if err != nil || len(envsA) == 0 {
		t.Fatalf("ImportV2 from Codex on A failed: %v", err)
	}

	for _, env := range envsA {
		if err := vA.SaveEntity(env); err != nil {
			t.Fatalf("SaveEntity on A failed: %v", err)
		}
	}

	// Machine A: Memory Analyze & Apply Proposal
	mcA := compiler.NewMemoryCompiler(compiler.NewTestBackend())
	analysisRes, err := mcA.Analyze(ctx, vA, "")
	if err != nil {
		t.Fatalf("Memory Compiler Analyze failed: %v", err)
	}

	if len(analysisRes.Proposals) > 0 {
		prop := analysisRes.Proposals[0]
		psA := governance.NewProposalStore(cfgA)
		_ = psA.SaveProposal(prop)

		if err := governance.ApplyProposals(vA, cfgA, []*compiler.Proposal{prop}); err != nil {
			t.Fatalf("ApplyProposals failed: %v", err)
		}
	}

	// Machine A: Context Compile & Export to Claude
	claudeAdA := claude.New(claudeRootA)
	budgetA := contextpkg.DefaultTokenBudget()
	ccA := contextpkg.NewContextCompiler(budgetA)
	manifestA, err := ccA.Compile(ctx, vA, "claude", claudeAdA.Capabilities())
	if err != nil || manifestA.CompiledContent == "" {
		t.Fatalf("Context Compile on A failed: %v", err)
	}

	exportPlanA, err := claudeAdA.PlanExportV2(ctx, manifestA)
	if err != nil {
		t.Fatalf("PlanExportV2 to Claude failed: %v", err)
	}
	_, err = claudeAdA.ApplyExport(ctx, exportPlanA)
	if err != nil {
		t.Fatalf("ApplyExport to Claude failed: %v", err)
	}

	// Machine A: Sync (push local vault state to encrypted git store)
	storeA := gitstore.New(cfgA)
	syncResA, err := storeA.Sync(ctx, vA, false)
	if err != nil {
		t.Fatalf("Sync on A failed: %v", err)
	}
	if syncResA.ObjectsEncryptedCount == 0 {
		t.Errorf("expected encrypted objects pushed from A")
	}

	// 2. Setup Computer B
	compBDir := filepath.Join(testDir, "machine_b")
	homeB := filepath.Join(compBDir, "home")
	vaultB := filepath.Join(compBDir, "vault")
	geminiRootB := filepath.Join(compBDir, "gemini")

	_ = os.MkdirAll(geminiRootB, 0700)

	t.Setenv(config.EnvAppHome, homeB)
	t.Setenv(config.EnvVaultDir, vaultB)

	cfgB, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load B failed: %v", err)
	}

	vB, err := vault.Initialize(cfgB)
	if err != nil {
		t.Fatalf("vault.Initialize B failed: %v", err)
	}

	// Copy encryption keys and vault metadata from A to B so B opens the same vault
	_ = os.MkdirAll(cfgB.KeysDir, 0700)
	_ = os.MkdirAll(cfgB.VaultDir, 0700)
	keyDataA, _ := os.ReadFile(filepath.Join(cfgA.KeysDir, "identity.age"))
	_ = os.WriteFile(filepath.Join(cfgB.KeysDir, "identity.age"), keyDataA, 0600)
	metaDataA, _ := os.ReadFile(filepath.Join(cfgA.VaultDir, "vault.json"))
	_ = os.WriteFile(filepath.Join(cfgB.VaultDir, "vault.json"), metaDataA, 0600)

	var errB error
	vB, errB = vault.LoadOpen(cfgB)
	if errB != nil {
		t.Fatalf("vault.LoadOpen B failed: %v", errB)
	}

	// Machine B: Export to Gemini
	geminiAdB := gemini.New(geminiRootB)
	ccB := contextpkg.NewContextCompiler(nil)
	manifestB, _ := ccB.Compile(ctx, vB, "gemini", geminiAdB.Capabilities())
	planB, err := geminiAdB.PlanExportV2(ctx, manifestB)
	if err != nil {
		t.Fatalf("PlanExportV2 on B failed: %v", err)
	}
	_, _ = geminiAdB.ApplyExport(ctx, planB)

	// 3. Delete one V2 entity on A
	entityToDelete := envsA[0].ID
	if err := vA.DeleteEntity(entityToDelete); err != nil {
		t.Fatalf("DeleteEntity on A failed: %v", err)
	}

	// Verify tombstone created on A
	if _, tombExists := vA.GetTombstone(entityToDelete); !tombExists {
		t.Fatalf("expected tombstone for deleted entity on A")
	}

	// Sync A then Sync B
	_, _ = storeA.Sync(ctx, vA, false)

	storeB := gitstore.New(cfgB)
	_, _ = storeB.Sync(ctx, vB, false)

	// Verify entity does NOT resurrect on B
	if _, existsOnB := vB.GetEntity(entityToDelete); existsOnB {
		t.Fatalf("deleted entity resurrected on Computer B after sync!")
	}

	t.Log("SUCCESS: Master End-to-End Corrective Checkpoint passed cleanly!")
}

func TestV2TombstonePropagationAcrossRealRemote(t *testing.T) {
	ctx := context.Background()
	testDir := t.TempDir()

	// 1. Setup real bare git remote repository
	remoteGitDir := filepath.Join(testDir, "remote.git")
	cmd := exec.CommandContext(ctx, "git", "init", "--bare", remoteGitDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed initializing bare git remote: %v (%s)", err, string(out))
	}

	// 2. Setup Computer A
	compADir := filepath.Join(testDir, "machine_a")
	homeA := filepath.Join(compADir, "home")
	vaultA := filepath.Join(compADir, "vault")

	t.Setenv(config.EnvAppHome, homeA)
	t.Setenv(config.EnvVaultDir, vaultA)

	cfgA, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load A failed: %v", err)
	}

	vA, err := vault.Initialize(cfgA)
	if err != nil {
		t.Fatalf("vault.Initialize A failed: %v", err)
	}

	storeA := gitstore.New(cfgA)
	if err := storeA.SetRemote(ctx, remoteGitDir); err != nil {
		t.Fatalf("SetRemote A failed: %v", err)
	}

	// Create V2 entity X on Machine A
	entityX := &model.EnvelopeV2{
		ID:            "apm_tombstone_propagation_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:  "Entity X to test real remote tombstone propagation",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	entityX.RevisionHash = model.ComputeRevisionHash(entityX)
	if err := vA.SaveEntity(entityX); err != nil {
		t.Fatalf("SaveEntity X on A failed: %v", err)
	}

	// Machine A Sync to real git remote
	if _, err := storeA.Sync(ctx, vA, false); err != nil {
		t.Fatalf("Sync A failed: %v", err)
	}

	// 3. Setup Computer B with same identity key
	compBDir := filepath.Join(testDir, "machine_b")
	homeB := filepath.Join(compBDir, "home")
	vaultB := filepath.Join(compBDir, "vault")

	t.Setenv(config.EnvAppHome, homeB)
	t.Setenv(config.EnvVaultDir, vaultB)

	cfgB, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load B failed: %v", err)
	}

	_ = cfgB.EnsureDirectories()
	keyDataA, _ := os.ReadFile(filepath.Join(cfgA.KeysDir, "identity.age"))
	_ = os.WriteFile(filepath.Join(cfgB.KeysDir, "identity.age"), keyDataA, 0600)
	metaDataA, _ := os.ReadFile(filepath.Join(cfgA.VaultDir, "vault.json"))
	_ = os.WriteFile(filepath.Join(cfgB.VaultDir, "vault.json"), metaDataA, 0600)

	vB, err := vault.LoadOpen(cfgB)
	if err != nil {
		t.Fatalf("vault.LoadOpen B failed: %v", err)
	}

	storeB := gitstore.New(cfgB)
	if err := storeB.SetRemote(ctx, remoteGitDir); err != nil {
		t.Fatalf("SetRemote B failed: %v", err)
	}

	// Machine B Sync (pulls entity X from real remote)
	if _, err := storeB.Sync(ctx, vB, false); err != nil {
		t.Fatalf("Sync B failed: %v", err)
	}

	// ASSERT 1: B has entity X
	if _, existsOnB := vB.GetEntity(entityX.ID); !existsOnB {
		t.Fatalf("expected Machine B to have Entity X after initial sync!")
	}

	// 4. Machine A deletes entity X and Syncs to remote
	if err := vA.DeleteEntity(entityX.ID); err != nil {
		t.Fatalf("DeleteEntity X on A failed: %v", err)
	}

	if _, err := storeA.Sync(ctx, vA, false); err != nil {
		t.Fatalf("Sync A after delete failed: %v", err)
	}

	// Machine B Syncs (pulls tombstone deletion from remote)
	if _, err := storeB.Sync(ctx, vB, false); err != nil {
		t.Fatalf("Sync B after delete failed: %v", err)
	}

	// ASSERT 2: B no longer has entity X
	if _, existsOnB := vB.GetEntity(entityX.ID); existsOnB {
		t.Fatalf("Entity X was NOT deleted on Machine B after remote tombstone sync!")
	}

	// 5. Subsequent Sync cycle on A and B (verify no resurrection and no tombstone loop)
	tombA1, _ := vA.ListTombstones()
	tombB1, _ := vB.ListTombstones()
	tombCountA1 := len(tombA1)
	tombCountB1 := len(tombB1)

	if _, err := storeA.Sync(ctx, vA, false); err != nil {
		t.Fatalf("second Sync A failed: %v", err)
	}
	if _, err := storeB.Sync(ctx, vB, false); err != nil {
		t.Fatalf("second Sync B failed: %v", err)
	}

	if _, existsOnB := vB.GetEntity(entityX.ID); existsOnB {
		t.Fatalf("Entity X resurrected on Machine B after second sync cycle!")
	}

	tombA2, _ := vA.ListTombstones()
	tombB2, _ := vB.ListTombstones()
	tombCountA2 := len(tombA2)
	tombCountB2 := len(tombB2)

	if tombCountA1 != tombCountA2 || tombCountB1 != tombCountB2 {
		t.Errorf("tombstone loop detected! Machine A tombstones %d -> %d, Machine B tombstones %d -> %d", tombCountA1, tombCountA2, tombCountB1, tombCountB2)
	}
}
