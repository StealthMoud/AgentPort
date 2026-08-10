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
	contextpkg "github.com/StealthMoud/AgentPort/internal/context"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/model"
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

	envsCodex, err := codexAdA.ImportV2(ctx, vaultA.Machine.MachineID, nil)
	if err != nil {
		t.Fatalf("Computer A Codex ImportV2 failed: %v", err)
	}
	for _, env := range envsCodex {
		_ = vaultA.SaveEntity(env)
	}

	envsClaude, err := claudeAdA.ImportV2(ctx, vaultA.Machine.MachineID, nil)
	if err != nil {
		t.Fatalf("Computer A Claude ImportV2 failed: %v", err)
	}
	for _, env := range envsClaude {
		_ = vaultA.SaveEntity(env)
	}

	// Safe Optimize & Validate on Computer A
	opt := optimizer.NewSafeOptimizer()
	_, err = opt.Optimize(vaultA, false)
	if err != nil {
		t.Fatalf("Computer A Optimize failed: %v", err)
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
	if syncResA.ObjectsEncryptedCount == 0 {
		t.Fatalf("expected objects encrypted on Computer A sync, got %d", syncResA.ObjectsEncryptedCount)
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
	if syncResB.ObjectsDecryptedCount == 0 {
		t.Fatalf("expected objects decrypted into Computer B vault, got %d", syncResB.ObjectsDecryptedCount)
	}

	entitiesB := vaultB.ListEntities()
	if len(entitiesB) == 0 {
		t.Fatalf("expected V2 entities in Computer B vault, got %d", len(entitiesB))
	}

	stateRootA := model.ComputeV2StateRoot(vaultA.ListEntities())
	stateRootB := model.ComputeV2StateRoot(entitiesB)
	if stateRootA != stateRootB {
		t.Fatalf("V2 state root mismatch across Computer A (%s) and Computer B (%s)", stateRootA, stateRootB)
	}

	// Export Computer B canonical state to Gemini CLI on Computer B
	geminiAdB := gemini.New(geminiRootB)
	ccB := contextpkg.NewContextCompiler(nil)
	manifestB, err := ccB.Compile(ctx, vaultB, "gemini", geminiAdB.Capabilities())
	if err != nil {
		t.Fatalf("ContextCompile on B failed: %v", err)
	}

	planB, err := geminiAdB.PlanExportV2(ctx, manifestB)
	if err != nil {
		t.Fatalf("Computer B Gemini PlanExportV2 failed: %v", err)
	}

	applyResB, err := geminiAdB.ApplyExport(ctx, planB)
	if err != nil {
		t.Fatalf("Computer B Gemini ApplyExport failed: %v", err)
	}
	if applyResB.AppliedCount == 0 {
		t.Fatalf("expected at least 1 item applied in Computer B Gemini export, got %d", applyResB.AppliedCount)
	}

	exportedGeminiFile := planB.Items[0].TargetPath
	exportedData, err := os.ReadFile(exportedGeminiFile)
	if err != nil {
		t.Fatalf("failed reading exported Gemini file on Computer B: %v", err)
	}

	if !strings.Contains(string(exportedData), "Mahmoud prefers Go 1.26") {
		t.Fatalf("exported content mismatch on Computer B Gemini: expected statement in %q", string(exportedData))
	}

	t.Log("SUCCESS: Cross-machine and cross-provider portability E2E test passed!")
}
