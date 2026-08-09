package optimizer_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/optimizer"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func TestSafeOptimizerDeduplicationAndProvenanceMerge(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	vaultDir := filepath.Join(tempDir, "vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, _ := config.Load()
	v, _ := vault.Initialize(cfg)

	// Create 2 artifacts with identical content from different sources
	art1 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindPreference,
		Scope:         model.ScopeGlobal,
		Title:         "Indentation Preference",
		Content:       "Use 2 spaces for tab stop.",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		Tags:          []string{"style", "formatting"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Provenance: []model.Provenance{
			{Provider: "claude", MachineID: "apm_1", SourcePath: "~/.claude/CLAUDE.md"},
		},
	}

	art2 := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindPreference,
		Scope:         model.ScopeGlobal,
		Title:         "Indentation Preference",
		Content:       "Use 2 spaces for tab stop.\r\n", // will normalize to identical content
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		Tags:          []string{"formatting", "tabs"},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Provenance: []model.Provenance{
			{Provider: "codex", MachineID: "apm_1", SourcePath: "~/.codex/instructions.md"},
		},
	}

	art1.ID = "apa_pref_claude_import"
	_ = v.SaveArtifact(art1)

	art2.ID = "apa_pref_codex_import"
	_ = v.SaveArtifact(art2)

	if len(v.ListArtifacts()) != 2 {
		t.Fatalf("expected 2 initial artifacts, got %d", len(v.ListArtifacts()))
	}

	opt := optimizer.NewSafeOptimizer()

	// Dry run test
	dryRes, err := opt.Optimize(v, true)
	if err != nil {
		t.Fatalf("dry run Optimize failed: %v", err)
	}
	if dryRes.ExactDuplicatesRemoved != 1 {
		t.Errorf("expected 1 duplicate detected in dry-run, got %d", dryRes.ExactDuplicatesRemoved)
	}
	if len(v.ListArtifacts()) != 2 {
		t.Errorf("dry run should not mutate vault, expected 2 artifacts, got %d", len(v.ListArtifacts()))
	}

	// Apply optimization
	res, err := opt.Optimize(v, false)
	if err != nil {
		t.Fatalf("Optimize apply failed: %v", err)
	}

	if res.AfterCount != 1 {
		t.Errorf("expected 1 remaining artifact after optimization, got %d", res.AfterCount)
	}

	remaining := v.ListArtifacts()
	if len(remaining) != 1 {
		t.Fatalf("expected 1 artifact in vault, got %d", len(remaining))
	}

	if len(remaining[0].Provenance) != 2 {
		t.Errorf("expected merged provenance of length 2, got %d", len(remaining[0].Provenance))
	}
}
