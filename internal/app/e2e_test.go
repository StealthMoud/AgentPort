package app_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/optimizer"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestEndToEndCrossMachineAndCrossProviderPortability(t *testing.T) {
	ctx := context.Background()
	tempRoot := t.TempDir()

	// 0. Setup a local bare Git repository to serve as remote origin
	bareRepoDir := filepath.Join(tempRoot, "bare_remote.git")
	cmd := exec.CommandContext(ctx, "git", "init", "--bare", bareRepoDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed initializing bare git remote: %v (%s)", err, string(out))
	}

	// ==========================================
	// COMPUTER A: Import state & Sync to remote
	// ==========================================
	compAHome := filepath.Join(tempRoot, "computer_a_home")
	compAVault := filepath.Join(tempRoot, "computer_a_vault")
	codexRoot := filepath.Join(tempRoot, "computer_a_codex")
	claudeRoot := filepath.Join(tempRoot, "computer_a_claude")

	_ = os.MkdirAll(codexRoot, 0700)
	_ = os.MkdirAll(claudeRoot, 0700)

	secretMemoryA := "Mahmoud prefers Go 1.26, strict type safety, and vibrant modern aesthetic designs."
	_ = os.WriteFile(filepath.Join(codexRoot, "instructions.md"), []byte(secretMemoryA), 0600)
	_ = os.WriteFile(filepath.Join(claudeRoot, "CLAUDE.md"), []byte(secretMemoryA), 0600)

	t.Setenv(config.EnvAppHome, compAHome)
	t.Setenv(config.EnvVaultDir, compAVault)

	cfgA, err := config.Load()
	if err != nil {
		t.Fatalf("Computer A config.Load failed: %v", err)
	}

	vaultA, err := vault.Initialize(cfgA)
	if err != nil {
		t.Fatalf("Computer A vault.Initialize failed: %v", err)
	}

	// Import from Codex & Claude on Computer A
	codexAdA := codex.New(codexRoot)
	claudeAdA := claude.New(claudeRoot)

	artsCodex, err := codexAdA.Import(ctx, vaultA.Machine.MachineID)
	if err != nil {
		t.Fatalf("Computer A Codex Import failed: %v", err)
	}
	for _, art := range artsCodex {
		_ = vaultA.SaveArtifact(art)
	}

	artsClaude, err := claudeAdA.Import(ctx, vaultA.Machine.MachineID)
	if err != nil {
		t.Fatalf("Computer A Claude Import failed: %v", err)
	}
	for _, art := range artsClaude {
		_ = vaultA.SaveArtifact(art)
	}

	// Safe Optimize & Validate on Computer A
	opt := optimizer.NewSafeOptimizer()
	optRes, err := opt.Optimize(vaultA, false)
	if err != nil {
		t.Fatalf("Computer A Optimize failed: %v", err)
	}
	if optRes.AfterCount != 1 {
		t.Fatalf("expected exact duplicates merged to 1 artifact on Computer A, got %d", optRes.AfterCount)
	}

	valA := vaultA.Validate()
	if !valA.Healthy {
		t.Fatalf("Computer A vault validation failed: %v", valA.Errors)
	}

	// Connect Computer A to local bare Git remote and Sync
	storeA := gitstore.New(cfgA)
	if err := storeA.SetRemote(ctx, bareRepoDir); err != nil {
		t.Fatalf("Computer A SetRemote failed: %v", err)
	}

	syncResA, err := storeA.Sync(ctx, vaultA, false)
	if err != nil {
		t.Fatalf("Computer A Sync failed: %v", err)
	}
	if syncResA.ObjectsEncryptedCount != 1 {
		t.Fatalf("expected 1 object encrypted on Computer A sync, got %d", syncResA.ObjectsEncryptedCount)
	}

	// Verify encryption boundary: Plaintext must NOT exist in SyncRepoDir
	_ = filepath.Walk(cfgA.SyncRepoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			if strings.Contains(string(data), secretMemoryA) {
				t.Fatalf("SECURITY VIOLATION: Plaintext memory leaked into sync repository file %s", path)
			}
			if strings.Contains(string(data), "AGE-SECRET-KEY-1") {
				t.Fatalf("SECURITY VIOLATION: Private Age encryption key leaked into sync repo file %s", path)
			}
		}
		return nil
	})

	// Export private key from Computer A to key file
	keyExportPath := filepath.Join(tempRoot, "exported_identity.age")
	if err := crypt.SaveIdentityToFile(vaultA.Key.Identity, keyExportPath); err != nil {
		t.Fatalf("failed exporting key from Computer A: %v", err)
	}

	// ==========================================
	// COMPUTER B: Restore state & Export to Gemini
	// ==========================================
	compBHome := filepath.Join(tempRoot, "computer_b_home")
	compBVault := filepath.Join(tempRoot, "computer_b_vault")
	geminiRootB := filepath.Join(tempRoot, "computer_b_gemini")

	_ = os.MkdirAll(geminiRootB, 0700)

	t.Setenv(config.EnvAppHome, compBHome)
	t.Setenv(config.EnvVaultDir, compBVault)

	cfgB, err := config.Load()
	if err != nil {
		t.Fatalf("Computer B config.Load failed: %v", err)
	}

	// Ensure keys directory on B and copy identity key from Computer A
	_ = cfgB.EnsureDirectories()
	keyPathB := filepath.Join(cfgB.KeysDir, "identity.age")
	keyData, _ := os.ReadFile(keyExportPath)
	_ = os.WriteFile(keyPathB, keyData, 0600)

	vaultB, err := vault.Initialize(cfgB)
	if err != nil {
		t.Fatalf("Computer B vault.Initialize failed: %v", err)
	}

	storeB := gitstore.New(cfgB)
	if err := storeB.SetRemote(ctx, bareRepoDir); err != nil {
		t.Fatalf("Computer B SetRemote failed: %v", err)
	}

	// Sync on Computer B (pulls remote objects & decrypts into Computer B vault)
	syncResB, err := storeB.Sync(ctx, vaultB, false)
	if err != nil {
		t.Fatalf("Computer B Sync failed: %v", err)
	}
	if syncResB.ObjectsDecryptedCount != 1 {
		t.Fatalf("expected 1 object decrypted into Computer B vault, got %d", syncResB.ObjectsDecryptedCount)
	}

	artifactsB := vaultB.ListArtifacts()
	if len(artifactsB) != 1 {
		t.Fatalf("expected 1 artifact in Computer B vault, got %d", len(artifactsB))
	}

	if artifactsB[0].Content != secretMemoryA {
		t.Fatalf("content mismatch on Computer B: expected %q, got %q", secretMemoryA, artifactsB[0].Content)
	}

	// Export Computer B canonical state to Gemini CLI on Computer B
	geminiAdB := gemini.New(geminiRootB)
	planB, err := geminiAdB.PlanExport(ctx, artifactsB)
	if err != nil {
		t.Fatalf("Computer B Gemini PlanExport failed: %v", err)
	}
	if len(planB.Items) > 0 {
		t.Logf("Gemini PlanExport Item Action: %s, TargetPath: %s, Reason: %s", planB.Items[0].Action, planB.Items[0].TargetPath, planB.Items[0].Reason)
	}

	applyResB, err := geminiAdB.ApplyExport(ctx, planB)
	if err != nil {
		t.Fatalf("Computer B Gemini ApplyExport failed: %v", err)
	}
	if applyResB.AppliedCount != 1 {
		t.Fatalf("expected 1 item applied in Computer B Gemini export, got %d", applyResB.AppliedCount)
	}

	exportedGeminiFile := planB.Items[0].TargetPath
	exportedData, err := os.ReadFile(exportedGeminiFile)
	if err != nil {
		t.Fatalf("failed reading exported Gemini file on Computer B: %v", err)
	}

	if string(exportedData) != secretMemoryA {
		t.Fatalf("exported content mismatch on Computer B Gemini: expected %q, got %q", secretMemoryA, string(exportedData))
	}

	t.Log("SUCCESS: Cross-machine and cross-provider portability E2E test passed!")
}
