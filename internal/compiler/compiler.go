package compiler

import (
	"context"
	"fmt"
	"sort"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type MemoryCompiler struct {
	backend Backend
}

func NewMemoryCompiler(b Backend) *MemoryCompiler {
	if b == nil {
		b = NewTestBackend()
	}
	return &MemoryCompiler{backend: b}
}

// ComputeStateRoot calculates deterministic SHA-256 state root for vault artifacts.
func ComputeStateRoot(artifacts []*model.Artifact) string {
	sorted := make([]*model.Artifact, len(artifacts))
	copy(sorted, artifacts)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	var totalFingerprints string
	for _, art := range sorted {
		totalFingerprints += art.ID + ":" + art.Fingerprint + "|"
	}

	return model.ComputeFingerprint(model.KindMemory, model.ScopeGlobal, "vault_state_root", totalFingerprints, nil)
}

// Analyze runs the memory compiler against the vault and returns proposed semantic operations.
func (mc *MemoryCompiler) Analyze(ctx context.Context, v *vault.Vault, scope model.Scope) (*AnalysisResponse, error) {
	if err := mc.backend.Health(ctx); err != nil {
		return nil, fmt.Errorf("memory compiler backend health check failed: %w", err)
	}

	artifacts := v.ListArtifacts()
	filtered := make([]*model.Artifact, 0, len(artifacts))

	for _, art := range artifacts {
		if scope != "" && art.Scope != scope {
			continue
		}
		if art.Kind == model.KindMemory || art.Kind == model.KindPreference || art.Kind == model.KindInstruction {
			filtered = append(filtered, art)
		}
	}

	stateRoot := ComputeStateRoot(filtered)

	req := &AnalysisRequest{
		Scope:          scope,
		InputStateRoot: stateRoot,
		Artifacts:      filtered,
	}

	res, err := mc.backend.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("backend analysis failed: %w", err)
	}

	// Validate all returned proposals
	for _, prop := range res.Proposals {
		if prop.ID == "" {
			prop.ID = model.GenerateEntityID("prop")
		}
		if prop.InputStateRoot == "" {
			prop.InputStateRoot = stateRoot
		}
	}

	return res, nil
}
