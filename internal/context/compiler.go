package context

import (
	"context"
	"fmt"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type TokenBudget struct {
	MaxTokens        int `json:"max_tokens"`
	InstructionsCap int `json:"instructions_cap"`
	PreferencesCap  int `json:"preferences_cap"`
	MemoryCap       int `json:"memory_cap"`
}

func DefaultTokenBudget() *TokenBudget {
	return &TokenBudget{
		MaxTokens:        12000,
		InstructionsCap: 4000,
		PreferencesCap:  3000,
		MemoryCap:       5000,
	}
}

type CompileItem struct {
	ArtifactID   string `json:"artifact_id"`
	Title        string `json:"title"`
	Kind         string `json:"kind"`
	Included     bool   `json:"included"`
	Reason       string `json:"reason"`
	EstTokenCost int    `json:"est_token_cost"`
}

type CompileManifest struct {
	TargetProvider    string         `json:"target_provider"`
	StateRoot         string         `json:"state_root"`
	Budget            *TokenBudget   `json:"budget"`
	TotalTokensEst    int            `json:"total_tokens_est"`
	Items             []*CompileItem `json:"items"`
	CompiledContent   string         `json:"compiled_content"`
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

// Compile selects canonical vault context for a target provider within a token budget.
func (cc *ContextCompiler) Compile(ctx context.Context, v *vault.Vault, providerName string, targetCap adapter.Capabilities) (*CompileManifest, error) {
	artifacts := v.ListArtifacts()

	manifest := &CompileManifest{
		TargetProvider:  providerName,
		Budget:          cc.budget,
		Items:           make([]*CompileItem, 0, len(artifacts)),
		CompiledContent: "",
	}

	usedTokens := 0

	for _, art := range artifacts {
		cost := EstimateTokens(art.Content)
		item := &CompileItem{
			ArtifactID:   art.ID,
			Title:        art.Title,
			Kind:         string(art.Kind),
			EstTokenCost: cost,
		}

		if targetCap.Instructions == adapter.SupportUnsupported && art.Kind == model.KindInstruction {
			item.Included = false
			item.Reason = fmt.Sprintf("provider %s does not support instructions", providerName)
			manifest.Items = append(manifest.Items, item)
			continue
		}

		if usedTokens+cost > cc.budget.MaxTokens {
			item.Included = false
			item.Reason = fmt.Sprintf("token budget limit reached (%d / %d tokens)", usedTokens+cost, cc.budget.MaxTokens)
			manifest.Items = append(manifest.Items, item)
			continue
		}

		item.Included = true
		item.Reason = "included in provider context allocation"
		usedTokens += cost
		manifest.Items = append(manifest.Items, item)

		if manifest.CompiledContent != "" {
			manifest.CompiledContent += "\n\n---\n\n"
		}
		manifest.CompiledContent += fmt.Sprintf("# %s\n%s", art.Title, art.Content)
	}

	manifest.TotalTokensEst = usedTokens
	return manifest, nil
}
