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
	MaxTokens         int `json:"max_tokens"`
	InstructionsCap   int `json:"instructions_cap"`
	PreferencesCap    int `json:"preferences_cap"`
	ProjectContextCap int `json:"project_context_cap"`
	MemoryCap         int `json:"memory_cap"`
}

func DefaultTokenBudget() *TokenBudget {
	return &TokenBudget{
		MaxTokens:         12000,
		InstructionsCap:   3000,
		PreferencesCap:    2000,
		ProjectContextCap: 3000,
		MemoryCap:         3000,
	}
}

type ContextCompiler struct {
	budget        *TokenBudget
	targetProject string
}

func NewContextCompiler(budget *TokenBudget) *ContextCompiler {
	if budget == nil {
		budget = DefaultTokenBudget()
	}
	return &ContextCompiler{budget: budget}
}

func (cc *ContextCompiler) SetTargetProjectID(projectID string) {
	cc.targetProject = projectID
}

// EstimateTokens calculates approximate token cost for text (roughly 4 chars per token).
func EstimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	return (len(text) + 3) / 4
}

// ComputePriorityV2 calculates numerical priority for deterministic sorting of V2 envelopes.
func ComputePriorityV2(env *model.EnvelopeV2) int {
	score := 10
	if env.Memory != nil {
		score += env.Memory.Importance * 5
	}
	if env.Scope == model.ScopeProject {
		score += 50
	}
	switch env.Kind {
	case model.KindInstructionV2:
		score += 100
	case model.KindPreferenceV2:
		score += 80
	case model.KindProjectContextV2:
		score += 70
	case model.KindSkillPackage:
		score += 65
	case model.KindAgentDef:
		score += 65
	case model.KindMemoryV2:
		score += 60
	}
	return score
}

// ComputePriorityV1 calculates priority for legacy V1 artifacts.
func ComputePriorityV1(art *model.Artifact) int {
	score := 10
	if art.Scope == model.ScopeProject {
		score += 50
	}
	switch art.Kind {
	case model.KindInstruction:
		score += 100
	case model.KindPreference:
		score += 80
	case model.KindProjectContext:
		score += 70
	case model.KindMemory:
		score += 60
	}
	return score
}

// Compile selects canonical vault context for a target provider within category token budgets deterministically.
func (cc *ContextCompiler) Compile(ctx context.Context, v *vault.Vault, providerName string, targetCap adapter.Capabilities) (*adapter.CompileManifest, error) {
	entities := v.ListEntities()
	v1Artifacts := v.ListArtifacts()

	stateRoot := model.ComputeV2StateRoot(entities)
	if len(entities) == 0 {
		stateRoot = compiler.ComputeStateRoot(v1Artifacts)
	}

	manifest := &adapter.CompileManifest{
		TargetProvider:  providerName,
		StateRoot:       stateRoot,
		Estimator:       "generic_char4",
		Budget:          cc.budget,
		Items:           make([]*adapter.CompileItem, 0),
		CompiledContent: "",
	}

	totalUsed := 0
	usedInstructions := 0
	usedPreferences := 0
	usedProjectContext := 0
	usedMemory := 0

	// 1. Process V2 Envelopes if present
	if len(entities) > 0 {
		var filtered []*model.EnvelopeV2
		for _, env := range entities {
			if env.Sensitivity == model.SensitivitySecret {
				continue
			}
			if env.Kind == model.KindSourceRecord {
				continue
			}
			if cc.targetProject != "" && env.Scope == model.ScopeProject && env.ProjectID != cc.targetProject {
				continue
			}
			if env.Memory != nil && env.Memory.Status != model.MemoryStatusActive {
				continue
			}
			filtered = append(filtered, env)
		}

		sort.Slice(filtered, func(i, j int) bool {
			pI, pJ := ComputePriorityV2(filtered[i]), ComputePriorityV2(filtered[j])
			if pI != pJ {
				return pI > pJ
			}
			if filtered[i].Scope != filtered[j].Scope {
				return filtered[i].Scope < filtered[j].Scope
			}
			return filtered[i].ID < filtered[j].ID
		})

		for _, env := range filtered {
			content := ""
			title := env.ID
			kindStr := string(env.Kind)

			if env.Memory != nil {
				content = env.Memory.Statement
				title = string(env.Kind)
			} else if env.Skill != nil {
				content = env.Skill.SkillMD
				title = env.Skill.Name
			} else if env.Agent != nil {
				content = env.Agent.Instructions
				title = env.Agent.Name
			} else if env.MCPTool != nil {
				content = env.MCPTool.Command
				title = env.MCPTool.Name
			}

			cost := EstimateTokens(content)
			prio := ComputePriorityV2(env)

			item := &adapter.CompileItem{
				ArtifactID:   env.ID,
				Title:        title,
				Kind:         kindStr,
				Scope:        string(env.Scope),
				Priority:     prio,
				EstTokenCost: cost,
				Content:      content,
			}

			if targetCap.Instructions == adapter.SupportUnsupported && env.Kind == model.KindInstructionV2 {
				item.Included = false
				item.Reason = fmt.Sprintf("provider %s does not support instructions", providerName)
				manifest.Items = append(manifest.Items, item)
				continue
			}

			if env.Kind == model.KindInstructionV2 && usedInstructions+cost > cc.budget.InstructionsCap {
				item.Included = false
				item.Reason = fmt.Sprintf("instructions category cap reached (%d / %d tokens)", usedInstructions+cost, cc.budget.InstructionsCap)
				manifest.Items = append(manifest.Items, item)
				continue
			}
			if env.Kind == model.KindPreferenceV2 && usedPreferences+cost > cc.budget.PreferencesCap {
				item.Included = false
				item.Reason = fmt.Sprintf("preferences category cap reached (%d / %d tokens)", usedPreferences+cost, cc.budget.PreferencesCap)
				manifest.Items = append(manifest.Items, item)
				continue
			}
			if env.Kind == model.KindProjectContextV2 && usedProjectContext+cost > cc.budget.ProjectContextCap {
				item.Included = false
				item.Reason = fmt.Sprintf("project context cap reached (%d / %d tokens)", usedProjectContext+cost, cc.budget.ProjectContextCap)
				manifest.Items = append(manifest.Items, item)
				continue
			}
			if env.Kind == model.KindMemoryV2 && usedMemory+cost > cc.budget.MemoryCap {
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
			switch env.Kind {
			case model.KindInstructionV2:
				usedInstructions += cost
			case model.KindPreferenceV2:
				usedPreferences += cost
			case model.KindProjectContextV2:
				usedProjectContext += cost
			case model.KindMemoryV2:
				usedMemory += cost
			}

			manifest.Items = append(manifest.Items, item)

			if manifest.CompiledContent != "" {
				manifest.CompiledContent += "\n\n---\n\n"
			}
			manifest.CompiledContent += fmt.Sprintf("# %s\n%s", title, content)
		}

		manifest.TotalTokensEst = totalUsed
		return manifest, nil
	}

	// 2. Fallback for legacy V1 artifacts
	sort.Slice(v1Artifacts, func(i, j int) bool {
		pI, pJ := ComputePriorityV1(v1Artifacts[i]), ComputePriorityV1(v1Artifacts[j])
		if pI != pJ {
			return pI > pJ
		}
		if v1Artifacts[i].Scope != v1Artifacts[j].Scope {
			return v1Artifacts[i].Scope < v1Artifacts[j].Scope
		}
		return v1Artifacts[i].ID < v1Artifacts[j].ID
	})

	for _, art := range v1Artifacts {
		if art.Sensitivity == model.SensitivitySecret {
			continue
		}
		cost := EstimateTokens(art.Content)
		prio := ComputePriorityV1(art)

		item := &adapter.CompileItem{
			ArtifactID:   art.ID,
			Title:        art.Title,
			Kind:         string(art.Kind),
			Scope:        string(art.Scope),
			Priority:     prio,
			EstTokenCost: cost,
			Content:      art.Content,
		}

		if targetCap.Instructions == adapter.SupportUnsupported && art.Kind == model.KindInstruction {
			item.Included = false
			item.Reason = fmt.Sprintf("provider %s does not support instructions", providerName)
			manifest.Items = append(manifest.Items, item)
			continue
		}

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
