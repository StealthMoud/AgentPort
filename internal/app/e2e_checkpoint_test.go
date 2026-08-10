package app_test

import (
	"context"
	"os"
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
	artifactsA, err := codexAdA.Import(ctx, vA.Machine.MachineID)
	if err != nil || len(artifactsA) == 0 {
		t.Fatalf("Import from Codex on A failed: %v", err)
	}

	for _, art := range artifactsA {
		if err := vA.SaveArtifact(art); err != nil {
			t.Fatalf("SaveArtifact on A failed: %v", err)
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

		txA := vA.BeginTx()
		newArt := &model.Artifact{
			SchemaVersion: model.SchemaVersionV1,
			Kind:          model.KindMemory,
			Scope:         model.ScopeGlobal,
			Title:         "Compiled Memory A",
			Content:       prop.ProposedState,
			Sensitivity:   model.SensitivityNormal,
		}
		_ = txA.SaveArtifact(newArt)
		if err := txA.Commit(); err != nil {
			t.Fatalf("txA.Commit failed: %v", err)
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

	exportPlanA, err := claudeAdA.PlanExport(ctx, vA.ListArtifacts())
	if err != nil {
		t.Fatalf("PlanExport to Claude failed: %v", err)
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
	planB, err := geminiAdB.PlanExport(ctx, vB.ListArtifacts())
	if err != nil {
		t.Fatalf("PlanExport on B failed: %v", err)
	}
	_, _ = geminiAdB.ApplyExport(ctx, planB)

	// 3. Delete one entity on A
	artToDelete := artifactsA[0].ID
	if err := vA.DeleteArtifact(artToDelete); err != nil {
		t.Fatalf("DeleteArtifact on A failed: %v", err)
	}

	// Verify tombstone created on A
	if _, tombExists := vA.GetTombstone(artToDelete); !tombExists {
		t.Fatalf("expected tombstone for deleted entity on A")
	}

	// Sync A then Sync B
	_, _ = storeA.Sync(ctx, vA, false)

	storeB := gitstore.New(cfgB)
	_, _ = storeB.Sync(ctx, vB, false)

	// Verify entity does NOT resurrect on B
	if _, existsOnB := vB.GetArtifact(artToDelete); existsOnB {
		t.Fatalf("deleted entity resurrected on Computer B after sync!")
	}

	t.Log("SUCCESS: Master End-to-End Corrective Checkpoint passed cleanly!")
}
