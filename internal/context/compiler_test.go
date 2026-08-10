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

func TestContextCompilerEstimatorLabel(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	cc := contextpkg.NewContextCompiler(nil)
	caps := adapter.Capabilities{Instructions: adapter.SupportFull}

	m, err := cc.Compile(ctx, v, "codex", caps)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if m.Estimator != "generic_char4" {
		t.Errorf("expected estimator label 'generic_char4', got %s", m.Estimator)
	}
}

func TestContextCompilerCategoryBudgets(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// Save oversized instruction exceeding budget
	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Oversized Instruction",
		Content:       "Very long instruction content string that exceeds the tight category token budget cap...",
	}
	_ = v.SaveArtifact(art)

	budget := &contextpkg.TokenBudget{
		MaxTokens:       1000,
		InstructionsCap: 2, // 2 token cap (~8 chars)
	}

	cc := contextpkg.NewContextCompiler(budget)
	caps := adapter.Capabilities{Instructions: adapter.SupportFull}

	m, err := cc.Compile(ctx, v, "codex", caps)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(m.Items) != 1 || m.Items[0].Included {
		t.Errorf("expected oversized instruction item to be excluded due to category budget cap")
	}
}

func TestContextCompilerWorkspaceIsolation(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	t.Setenv(config.EnvAppHome, filepath.Join(tempDir, "home"))
	t.Setenv(config.EnvVaultDir, filepath.Join(tempDir, "vault"))

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// 1. Global memory
	envGlobal := &model.EnvelopeV2{
		ID:            "apm_global_mem",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Memory: &model.MemoryPayload{
			Statement:  "Global memory available everywhere",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	envGlobal.RevisionHash = model.ComputeRevisionHash(envGlobal)
	_ = v.SaveEntity(envGlobal)

	// 2. Project A memory
	envProjA := &model.EnvelopeV2{
		ID:            "apm_proja_mem",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeProject,
		ProjectID:     "proj_A",
		Memory: &model.MemoryPayload{
			Statement:  "Project A specific memory",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	envProjA.RevisionHash = model.ComputeRevisionHash(envProjA)
	_ = v.SaveEntity(envProjA)

	// 3. Project B memory
	envProjB := &model.EnvelopeV2{
		ID:            "apm_projb_mem",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeProject,
		ProjectID:     "proj_B",
		Memory: &model.MemoryPayload{
			Statement:  "Project B specific memory",
			Category:   model.CategoryWorkflow,
			Status:     model.MemoryStatusActive,
			Importance: 8,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}
	envProjB.RevisionHash = model.ComputeRevisionHash(envProjB)
	_ = v.SaveEntity(envProjB)

	// Compile for Project A
	cc := contextpkg.NewContextCompiler(nil)
	cc.SetTargetProjectID("proj_A")

	caps := adapter.Capabilities{Memory: adapter.SupportFull}
	m, err := cc.Compile(ctx, v, "codex", caps)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	includedIDs := make(map[string]bool)
	for _, item := range m.Items {
		if item.Included {
			includedIDs[item.ArtifactID] = true
		}
	}

	if !includedIDs["apm_global_mem"] {
		t.Errorf("expected global memory apm_global_mem to be included")
	}
	if !includedIDs["apm_proja_mem"] {
		t.Errorf("expected target project A memory apm_proja_mem to be included")
	}
	if includedIDs["apm_projb_mem"] {
		t.Errorf("project B memory apm_projb_mem LEAKED into project A compile manifest!")
	}
}
