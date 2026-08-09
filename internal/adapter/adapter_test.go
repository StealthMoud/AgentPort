package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
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
