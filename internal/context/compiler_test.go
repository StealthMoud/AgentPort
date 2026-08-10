package context_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/config"
	contextpkg "github.com/StealthMoud/AgentPort/internal/context"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestContextCompilerDeterminismAndCategoryBudgets(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	v, err := vault.Initialize(cfg)
	if err != nil {
		t.Fatalf("vault.Initialize failed: %v", err)
	}

	// 1. Add instructions and memories
	art1 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Instruction 1",
		Content:       "Always use clean architecture and typed handlers.",
		CreatedAt:     time.Now(),
	}
	art2 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindPreference,
		Scope:         model.ScopeGlobal,
		Title:         "Preference 1",
		Content:       "User prefers Go and dark theme.",
		CreatedAt:     time.Now(),
	}
	_ = v.SaveArtifact(art1)
	_ = v.SaveArtifact(art2)

	budget := &contextpkg.TokenBudget{
		MaxTokens:       1000,
		InstructionsCap: 500,
		PreferencesCap:  500,
		MemoryCap:       500,
	}

	caps := adapter.Capabilities{
		Instructions: adapter.SupportFull,
		Memory:       adapter.SupportFull,
	}

	cc := contextpkg.NewContextCompiler(budget)

	// Run 1
	m1, err := cc.Compile(ctx, v, "codex", caps)
	if err != nil {
		t.Fatalf("Compile run 1 failed: %v", err)
	}

	// Run 2
	m2, err := cc.Compile(ctx, v, "codex", caps)
	if err != nil {
		t.Fatalf("Compile run 2 failed: %v", err)
	}

	// Assert byte-identical output (determinism)
	if m1.CompiledContent != m2.CompiledContent {
		t.Errorf("expected byte-identical compiled content across runs, got diff:\nRun 1: %s\nRun 2: %s", m1.CompiledContent, m2.CompiledContent)
	}
	if m1.StateRoot == "" {
		t.Errorf("expected non-empty state root in manifest")
	}
	if m1.StateRoot != m2.StateRoot {
		t.Errorf("expected identical state root, got %s vs %s", m1.StateRoot, m2.StateRoot)
	}
}
