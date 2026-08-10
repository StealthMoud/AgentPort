package adapter_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func filterNonSourceRecord(envs []*model.EnvelopeV2) []*model.EnvelopeV2 {
	res := make([]*model.EnvelopeV2, 0)
	for _, env := range envs {
		if env.Kind != model.KindSourceRecord {
			res = append(res, env)
		}
	}
	return res
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

	typedEnvs := filterNonSourceRecord(v2Envs)
	if len(typedEnvs) != 1 {
		t.Fatalf("expected 1 typed V2 envelope, got %d", len(typedEnvs))
	}
	if typedEnvs[0].Kind != model.KindSkillPackage {
		t.Fatalf("expected KindSkillPackage, got %s", typedEnvs[0].Kind)
	}
	if typedEnvs[0].Skill == nil || typedEnvs[0].Skill.SkillMD == "" {
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

	typedEnvs := filterNonSourceRecord(v2Envs)
	if len(typedEnvs) != 1 {
		t.Fatalf("expected 1 typed V2 envelope, got %d", len(typedEnvs))
	}
	if typedEnvs[0].Kind != model.KindAgentDef {
		t.Fatalf("expected KindAgentDef, got %s", typedEnvs[0].Kind)
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

	typedEnvs := filterNonSourceRecord(v2Envs)
	if len(typedEnvs) != 1 {
		t.Fatalf("expected 1 typed V2 envelope, got %d", len(typedEnvs))
	}
	env := typedEnvs[0]
	if env.Kind != model.KindMCPToolDef {
		t.Fatalf("expected KindMCPToolDef, got %s", env.Kind)
	}

	if env.MCPTool == nil {
		t.Fatalf("expected MCPTool payload")
	}

	if !env.MCPTool.RequiresCredential {
		t.Errorf("expected RequiresCredential == true")
	}

	foundKey := false
	for _, name := range env.MCPTool.EnvVarNames {
		if name == "API_KEY" {
			foundKey = true
			break
		}
	}
	if !foundKey {
		t.Errorf("expected env var name API_KEY to be preserved in EnvVarNames")
	}

	data, _ := json.Marshal(env)
	if strings.Contains(string(data), "secret_token") {
		t.Errorf("secret literal 'secret_token' MUST NOT occur anywhere in EnvelopeV2, got: %s", string(data))
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

	typedEnvs := filterNonSourceRecord(v2Envs)
	if len(typedEnvs) != 1 {
		t.Fatalf("expected 1 typed V2 envelope, got %d", len(typedEnvs))
	}
	if typedEnvs[0].Scope != model.ScopeProject || typedEnvs[0].ProjectID != "proj_123" {
		t.Errorf("expected ScopeProject and ProjectID proj_123, got Scope %s and ProjectID %s", typedEnvs[0].Scope, typedEnvs[0].ProjectID)
	}
}

func TestReimportIdempotency(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	instPath := filepath.Join(root, "AGENTS.md")
	_ = os.WriteFile(instPath, []byte("Initial agent instruction."), 0600)

	codexAd := codex.New(root)

	// Import 1
	envs1, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("Import 1 failed: %v", err)
	}
	typed1 := filterNonSourceRecord(envs1)
	if len(typed1) != 1 {
		t.Fatalf("expected 1 typed envelope on import 1, got %d", len(typed1))
	}
	initialID := typed1[0].ID
	initialHash := typed1[0].RevisionHash

	// Import 2 (unchanged file)
	envs2, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("Import 2 failed: %v", err)
	}
	typed2 := filterNonSourceRecord(envs2)
	if len(typed2) != 1 {
		t.Fatalf("expected 1 typed envelope on import 2, got %d", len(typed2))
	}

	if typed2[0].ID != initialID {
		t.Errorf("stable entity ID changed across re-imports of unchanged file: %s vs %s", initialID, typed2[0].ID)
	}
	if typed2[0].RevisionHash != initialHash {
		t.Errorf("revision hash changed across re-imports of unchanged file: %s vs %s", initialHash, typed2[0].RevisionHash)
	}

	// Import 3 (modified file content)
	_ = os.WriteFile(instPath, []byte("Modified agent instruction content!"), 0600)
	envs3, err := codexAd.ImportV2(ctx, "apm_test_machine", nil)
	if err != nil {
		t.Fatalf("Import 3 failed: %v", err)
	}
	typed3 := filterNonSourceRecord(envs3)
	if len(typed3) != 1 {
		t.Fatalf("expected 1 typed envelope on import 3, got %d", len(typed3))
	}

	if typed3[0].ID != initialID {
		t.Errorf("stable entity ID changed after modifying content: %s vs %s", initialID, typed3[0].ID)
	}
	if typed3[0].RevisionHash == initialHash {
		t.Errorf("expected revision hash to change after modifying content, got identical hash: %s", initialHash)
	}
}
