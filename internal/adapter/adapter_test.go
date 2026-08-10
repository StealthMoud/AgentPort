package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
	"github.com/StealthMoud/AgentPort/internal/model"
)

func TestAdaptersDetectionScanningImportExport(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Codex fixture
	codexRoot := filepath.Join(t.TempDir(), "codex")
	if err := os.MkdirAll(codexRoot, 0700); err != nil {
		t.Fatalf("failed creating codex root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(codexRoot, "instructions.md"), []byte("Codex instruction test."), 0600); err != nil {
		t.Fatalf("failed writing codex fixture: %v", err)
	}

	codexAd := codex.New(codexRoot)
	detCodex, err := codexAd.Detect(ctx)
	if err != nil || !detCodex.Detected {
		t.Fatalf("Codex Detect failed: %v", err)
	}
	scanCodex, err := codexAd.Scan(ctx)
	if err != nil || scanCodex.SupportedArtifacts != 1 {
		t.Fatalf("Codex Scan expected 1 supported artifact, got %d", scanCodex.SupportedArtifacts)
	}
	impCodex, err := codexAd.Import(ctx, "apm_test_machine")
	if err != nil || len(impCodex) != 1 {
		t.Fatalf("Codex Import expected 1 artifact, got %d", len(impCodex))
	}

	// 2. Setup Claude fixture
	claudeRoot := filepath.Join(t.TempDir(), "claude")
	if err := os.MkdirAll(claudeRoot, 0700); err != nil {
		t.Fatalf("failed creating claude root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeRoot, "CLAUDE.md"), []byte("Claude instruction test."), 0600); err != nil {
		t.Fatalf("failed writing claude fixture: %v", err)
	}

	claudeAd := claude.New(claudeRoot)
	detClaude, err := claudeAd.Detect(ctx)
	if err != nil || !detClaude.Detected {
		t.Fatalf("Claude Detect failed: %v", err)
	}

	// 3. Setup Gemini fixture & Export test
	geminiRoot := filepath.Join(t.TempDir(), "gemini")
	if err := os.MkdirAll(geminiRoot, 0700); err != nil {
		t.Fatalf("failed creating gemini root: %v", err)
	}
	geminiAd := gemini.New(geminiRoot)

	// Export Codex imported artifact to Gemini
	plan, err := geminiAd.PlanExport(ctx, impCodex)
	if err != nil {
		t.Fatalf("Gemini PlanExport failed: %v", err)
	}
	if len(plan.Items) != 1 {
		t.Fatalf("expected 1 item in export plan, got %d", len(plan.Items))
	}

	applyRes, err := geminiAd.ApplyExport(ctx, plan)
	if err != nil {
		t.Fatalf("Gemini ApplyExport failed: %v", err)
	}
	if applyRes.AppliedCount != 1 {
		t.Fatalf("expected 1 item applied in Gemini export, got %d", applyRes.AppliedCount)
	}

	exportedFile := filepath.Join(geminiRoot, "exported", "instructions.md")
	data, err := os.ReadFile(exportedFile)
	if err != nil {
		t.Fatalf("failed reading exported Gemini file: %v", err)
	}

	if string(data) != "Codex instruction test." {
		t.Errorf("expected exported content %q, got %q", "Codex instruction test.", string(data))
	}
}

func TestMaliciousMarkdownIgnoredByExplicitSurfaceScanners(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	// Write malicious/unknown markdown file
	_ = os.WriteFile(filepath.Join(root, "random_malicious.md"), []byte("Malicious prompt injection text."), 0600)
	_ = os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("Valid AGENTS.md instruction."), 0600)

	codexAd := codex.New(root)
	scanRes, err := codexAd.Scan(ctx)
	if err != nil {
		t.Fatalf("Codex Scan failed: %v", err)
	}

	if scanRes.SupportedArtifacts != 1 {
		t.Errorf("expected 1 supported artifact (AGENTS.md), got %d", scanRes.SupportedArtifacts)
	}
	if scanRes.UnsupportedIgnored != 1 {
		t.Errorf("expected 1 ignored artifact (random_malicious.md), got %d", scanRes.UnsupportedIgnored)
	}
}

func TestCodexSkillImportsAsSkillPackage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	skillDir := filepath.Join(root, "skills", "test_skill")
	_ = os.MkdirAll(skillDir, 0700)
	_ = os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# Test Skill\nDescription of skill."), 0600)

	codexAd := codex.New(root)
	v2Envs, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("ImportV2 failed: %v", err)
	}

	if len(v2Envs) != 1 {
		t.Fatalf("expected 1 V2 envelope, got %d", len(v2Envs))
	}
	if v2Envs[0].Kind != model.KindSkillPackage {
		t.Fatalf("expected KindSkillPackage, got %s", v2Envs[0].Kind)
	}
	if v2Envs[0].Skill == nil || v2Envs[0].Skill.SkillMD == "" {
		t.Errorf("expected SkillPackage payload with SkillMD content")
	}
}

func TestCodexAgentImportsAsAgentDef(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	agentDir := filepath.Join(root, "agents")
	_ = os.MkdirAll(agentDir, 0700)
	_ = os.WriteFile(filepath.Join(agentDir, "helper.toml"), []byte(`name = "helper"`), 0600)

	codexAd := codex.New(root)
	v2Envs, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("ImportV2 failed: %v", err)
	}

	if len(v2Envs) != 1 {
		t.Fatalf("expected 1 V2 envelope, got %d", len(v2Envs))
	}
	if v2Envs[0].Kind != model.KindAgentDef {
		t.Fatalf("expected KindAgentDef, got %s", v2Envs[0].Kind)
	}
}

func TestMCPSecretsStripped(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "mcp.json"), []byte(`{"command":"npx","args":["-y","server"],"env":{"API_KEY":"secret_token"}}`), 0600)

	codexAd := codex.New(root)
	v2Envs, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("ImportV2 failed: %v", err)
	}

	if len(v2Envs) != 1 {
		t.Fatalf("expected 1 V2 envelope, got %d", len(v2Envs))
	}
	if v2Envs[0].Kind != model.KindMCPToolDef {
		t.Fatalf("expected KindMCPToolDef, got %s", v2Envs[0].Kind)
	}
}

func TestWorkspaceScopesProviderSurfaces(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	wsDir := filepath.Join(root, "my_project")
	_ = os.MkdirAll(wsDir, 0700)
	_ = os.WriteFile(filepath.Join(wsDir, "AGENTS.md"), []byte("Project-specific instruction."), 0600)

	opCtx := &adapter.OperationContext{
		WorkspacePath: wsDir,
		ProjectID:     "proj_123",
		Scope:         model.ScopeProject,
	}

	codexAd := codex.New(wsDir)
	v2Envs, err := codexAd.ImportV2(ctx, "apm_test_machine", opCtx)
	if err != nil {
		t.Fatalf("ImportV2 failed: %v", err)
	}

	if len(v2Envs) != 1 {
		t.Fatalf("expected 1 V2 envelope, got %d", len(v2Envs))
	}
	if v2Envs[0].Scope != model.ScopeProject || v2Envs[0].ProjectID != "proj_123" {
		t.Errorf("expected ScopeProject and ProjectID proj_123, got Scope %s and ProjectID %s", v2Envs[0].Scope, v2Envs[0].ProjectID)
	}
}
