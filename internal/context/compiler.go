package context

import (
	"context"
	"fmt"
	"sort"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type TokenBudget struct {
	MaxTokens       int `json:"max_tokens"`
	InstructionsCap int `json:"instructions_cap"`
	PreferencesCap  int `json:"preferences_cap"`
	MemoryCap       int `json:"memory_cap"`
}

func DefaultTokenBudget() *TokenBudget {
	return &TokenBudget{
		MaxTokens:       12000,
		InstructionsCap: 4000,
		PreferencesCap:  3000,
		MemoryCap:       5000,
	}
}

type CompileItem struct {
	ArtifactID   string `json:"artifact_id"`
	Title        string `json:"title"`
	Kind         string `json:"kind"`
	Scope        string `json:"scope"`
	Priority     int    `json:"priority"`
	Included     bool   `json:"included"`
	Reason       string `json:"reason"`
	EstTokenCost int    `json:"est_token_cost"`
}

type CompileManifest struct {
	TargetProvider  string         `json:"target_provider"`
	StateRoot       string         `json:"state_root"`
	WorkspacePath   string         `json:"workspace_path,omitempty"`
	Budget          *TokenBudget   `json:"budget"`
	TotalTokensEst  int            `json:"total_tokens_est"`
	Items           []*CompileItem `json:"items"`
	CompiledContent string         `json:"compiled_content"`
}

type ContextCompiler struct {
	budget *TokenBudget
}

func NewContextCompiler(budget *TokenBudget) *ContextCompiler {
	if budget == nil {
		budget = DefaultTokenBudget()
	}
	return &ContextCompiler{budget: budget}
}

// EstimateTokens calculates approximate token cost for text (roughly 4 chars per token).
func EstimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	return (len(text) + 3) / 4
}

// ComputePriority calculates numerical priority for deterministic sorting (higher score first).
func ComputePriority(art *model.Artifact) int {
	score := 10
	if art.Scope == model.ScopeProject {
		score += 50
	}
	switch art.Kind {
	case model.KindInstruction:
		score += 100
	case model.KindPreference:
		score += 80
	case model.KindMemory:
		score += 60
	case model.KindProjectContext:
		score += 70
	}
	return score
}

// Compile selects canonical vault context for a target provider within category token budgets deterministically.
func (cc *ContextCompiler) Compile(ctx context.Context, v *vault.Vault, providerName string, targetCap adapter.Capabilities) (*CompileManifest, error) {
	artifacts := v.ListArtifacts()

	// Sort artifacts deterministically by Priority -> Scope -> ID
	sort.Slice(artifacts, func(i, j int) bool {
		pI, pJ := ComputePriority(artifacts[i]), ComputePriority(artifacts[j])
		if pI != pJ {
			return pI > pJ
		}
		if artifacts[i].Scope != artifacts[j].Scope {
			return artifacts[i].Scope < artifacts[j].Scope
		}
		return artifacts[i].ID < artifacts[j].ID
	})

	stateRoot := compiler.ComputeStateRoot(artifacts)

	manifest := &CompileManifest{
		TargetProvider:  providerName,
		StateRoot:       stateRoot,
		Budget:          cc.budget,
		Items:           make([]*CompileItem, 0, len(artifacts)),
		CompiledContent: "",
	}

	totalUsed := 0
	usedInstructions := 0
	usedPreferences := 0
	usedMemory := 0

	for _, art := range artifacts {
		cost := EstimateTokens(art.Content)
		prio := ComputePriority(art)

		item := &CompileItem{
			ArtifactID:   art.ID,
			Title:        art.Title,
			Kind:         string(art.Kind),
			Scope:        string(art.Scope),
			Priority:     prio,
			EstTokenCost: cost,
		}

		if targetCap.Instructions == adapter.SupportUnsupported && art.Kind == model.KindInstruction {
			item.Included = false
			item.Reason = fmt.Sprintf("provider %s does not support instructions", providerName)
			manifest.Items = append(manifest.Items, item)
			continue
		}

		// Enforce Category Token Budgets
		if art.Kind == model.KindInstruction && usedInstructions+cost > cc.budget.InstructionsCap {
			item.Included = false
			item.Reason = fmt.Sprintf("instructions category cap reached (%d / %d tokens)", usedInstructions+cost, cc.budget.InstructionsCap)
			manifest.Items = append(manifest.Items, item)
			continue
		}
		if art.Kind == model.KindPreference && usedPreferences+cost > cc.budget.PreferencesCap {
			item.Included = false
			item.Reason = fmt.Sprintf("preferences category cap reached (%d / %d tokens)", usedPreferences+cost, cc.budget.PreferencesCap)
			manifest.Items = append(manifest.Items, item)
			continue
		}
		if art.Kind == model.KindMemory && usedMemory+cost > cc.budget.MemoryCap {
			item.Included = false
			item.Reason = fmt.Sprintf("memory category cap reached (%d / %d tokens)", usedMemory+cost, cc.budget.MemoryCap)
			manifest.Items = append(manifest.Items, item)
			continue
		}

		if totalUsed+cost > cc.budget.MaxTokens {
			item.Included = false
			item.Reason = fmt.Sprintf("total max token budget limit reached (%d / %d tokens)", totalUsed+cost, cc.budget.MaxTokens)
			manifest.Items = append(manifest.Items, item)
			continue
		}

		item.Included = true
		item.Reason = "included in provider context allocation"
		totalUsed += cost
		switch art.Kind {
		case model.KindInstruction:
			usedInstructions += cost
		case model.KindPreference:
			usedPreferences += cost
		case model.KindMemory:
			usedMemory += cost
		}

		manifest.Items = append(manifest.Items, item)

		if manifest.CompiledContent != "" {
			manifest.CompiledContent += "\n\n---\n\n"
		}
		manifest.CompiledContent += fmt.Sprintf("# %s\n%s", art.Title, art.Content)
	}

	manifest.TotalTokensEst = totalUsed
	return manifest, nil
}
