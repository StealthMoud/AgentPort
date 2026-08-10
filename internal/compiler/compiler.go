package compiler

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type MemoryCompiler struct {
	backend            Backend
	allowPrivateRemote bool
}

func NewMemoryCompiler(b Backend) *MemoryCompiler {
	if b == nil {
		b = NewTestBackend()
	}
	return &MemoryCompiler{backend: b}
}

func (mc *MemoryCompiler) SetAllowPrivateRemote(allow bool) {
	mc.allowPrivateRemote = allow
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

// ComputeV2StateRoot calculates state root for V2 entities.
func ComputeV2StateRoot(entities []*model.EnvelopeV2) string {
	return model.ComputeV2StateRoot(entities)
}

// ValidateProposal performs strict untrusted model output validation.
func ValidateProposal(prop *Proposal, validIDs map[string]bool, stateRoot string) error {
	if prop.ID == "" {
		return fmt.Errorf("%w: proposal missing ID", ErrInvalidProposal)
	}

	switch prop.Operation {
	case OpCreate, OpMerge, OpRefine, OpSupersede, OpArchive, OpMarkConflict, OpMarkStale, OpReclassify:
		// Valid enum
	default:
		return fmt.Errorf("%w: invalid operation %s", ErrInvalidProposal, prop.Operation)
	}

	if prop.Confidence < 0.0 || prop.Confidence > 1.0 {
		return fmt.Errorf("%w: confidence %.2f out of bounds [0, 1]", ErrInvalidProposal, prop.Confidence)
	}

	// Verify all target IDs exist in validIDs map (reject hallucinated target IDs)
	for _, targetID := range prop.TargetIDs {
		if !validIDs[targetID] {
			return fmt.Errorf("%w: target ID %s does not exist in vault (hallucination rejected)", ErrInvalidProposal, targetID)
		}
	}

	// Security scan proposed state for prompt injection / secrets / shell code
	if hasSecret, reason := security.ScanContentForSecrets(prop.ProposedState); hasSecret {
		return fmt.Errorf("%w: proposed state contained secret: %s", ErrInvalidProposal, reason)
	}

	if strings.Contains(prop.ProposedState, "<script>") || strings.Contains(prop.ProposedState, "eval(") {
		return fmt.Errorf("%w: proposed state contained disallowed script code", ErrInvalidProposal)
	}

	return nil
}

// Analyze runs the memory compiler against the vault, enforcing privacy policies and strict proposal validation.
func (mc *MemoryCompiler) Analyze(ctx context.Context, v *vault.Vault, scope model.Scope) (*AnalysisResponse, error) {
	if err := mc.backend.Health(ctx); err != nil {
		return nil, fmt.Errorf("memory compiler backend health check failed: %w", err)
	}

	isRemoteBackend := mc.backend.Name() == "openai" || mc.backend.Name() == "anthropic" || mc.backend.Name() == "gemini"

	artifacts := v.ListArtifacts()
	filtered := make([]*model.Artifact, 0, len(artifacts))
	validIDs := make(map[string]bool)

	for _, art := range artifacts {
		// SensitivitySecret is NEVER sent to any model backend
		if art.Sensitivity == model.SensitivitySecret {
			continue
		}
		// SensitivityPrivate requires explicit opt-in for remote backends
		if art.Sensitivity == model.SensitivityPrivate && isRemoteBackend && !mc.allowPrivateRemote {
			continue
		}
		if scope != "" && art.Scope != scope {
			continue
		}
		if art.Kind == model.KindMemory || art.Kind == model.KindPreference || art.Kind == model.KindInstruction {
			filtered = append(filtered, art)
			validIDs[art.ID] = true
		}
	}

	entities := v.ListEntities()
	filteredEntities := make([]*model.EnvelopeV2, 0, len(entities))
	for _, env := range entities {
		// SensitivitySecret is NEVER sent to any model backend
		if env.Sensitivity == model.SensitivitySecret {
			continue
		}
		// SensitivityPrivate requires explicit opt-in for remote backends
		if env.Sensitivity == model.SensitivityPrivate && isRemoteBackend && !mc.allowPrivateRemote {
			continue
		}
		if scope != "" && env.Scope != scope {
			continue
		}
		filteredEntities = append(filteredEntities, env)
		validIDs[env.ID] = true
	}

	stateRoot := model.ComputeV2StateRoot(entities)
	if len(entities) == 0 {
		stateRoot = ComputeStateRoot(filtered)
	}

	req := &AnalysisRequest{
		Scope:          scope,
		InputStateRoot: stateRoot,
		Artifacts:      filtered,
		Entities:       filteredEntities,
	}

	res, err := mc.backend.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("backend analysis failed: %w", err)
	}

	validatedProposals := make([]*Proposal, 0, len(res.Proposals))
	for _, prop := range res.Proposals {
		if prop.ID == "" {
			prop.ID = model.GenerateEntityID("prop")
		}
		prop.InputStateRoot = stateRoot
		prop.Backend = mc.backend.Name()

		if err := ValidateProposal(prop, validIDs, stateRoot); err != nil {
			// Skip unvalidated or hallucinated proposals safely
			continue
		}

		validatedProposals = append(validatedProposals, prop)
	}

	res.StateRoot = stateRoot
	res.Proposals = validatedProposals
	return res, nil
}
