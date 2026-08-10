package gemini

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
)

type GeminiAdapter struct {
	customRoot string
}

func New(customRoot string) *GeminiAdapter {
	return &GeminiAdapter{customRoot: customRoot}
}

func (g *GeminiAdapter) Name() string {
	return "gemini"
}

func (g *GeminiAdapter) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{
		Instructions: adapter.SupportFull,
		Memory:       adapter.SupportFull,
		Skills:       adapter.SupportPartial,
		Agents:       adapter.SupportPartial,
		MCP:          adapter.SupportPartial,
		ProjectRules: adapter.SupportFull,
	}
}

func (g *GeminiAdapter) resolveRoot() (string, error) {
	if g.customRoot != "" {
		return g.customRoot, nil
	}
	if env := os.Getenv("GEMINI_HOME"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gemini"), nil
}

func (g *GeminiAdapter) Detect(ctx context.Context) (*adapter.DetectResult, error) {
	root, err := g.resolveRoot()
	if err != nil {
		return &adapter.DetectResult{Provider: g.Name(), Detected: false, Message: err.Error()}, nil
	}

	info, err := os.Stat(root)
	if err == nil && info.IsDir() {
		return &adapter.DetectResult{
			Provider: g.Name(),
			Detected: true,
			RootPath: root,
			Message:  "Gemini CLI directory detected",
		}, nil
	}

	return &adapter.DetectResult{
		Provider: g.Name(),
		Detected: false,
		RootPath: root,
		Message:  "Gemini CLI installation not found",
	}, nil
}

func (g *GeminiAdapter) Scan(ctx context.Context) (*adapter.ScanResult, error) {
	root, _ := g.resolveRoot()
	res := &adapter.ScanResult{
		Provider: g.Name(),
		Details:  make([]adapter.ScanDetail, 0),
	}

	if _, err := os.Stat(root); os.IsNotExist(err) {
		return res, nil
	}

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		secRes := security.InspectFileName(path)
		if secRes.Decision == security.DecisionReject {
			res.RejectedBySecurity++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "rejected",
				Reason: secRes.Reason,
			})
			return nil
		}

		if secRes.Decision == security.DecisionIgnore {
			res.UnsupportedIgnored++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "ignored",
				Reason: secRes.Reason,
			})
			return nil
		}

		isSurface, reason, kind := isExplicitGeminiSurface(path)
		if isSurface {
			res.SupportedArtifacts++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "supported",
				Reason: reason,
				Kind:   string(kind),
			})
		} else {
			res.UnsupportedIgnored++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "ignored",
				Reason: "unrecognized or unlisted provider surface",
			})
		}

		return nil
	})

	return res, nil
}

func isExplicitGeminiSurface(path string) (bool, string, string) {
	base := strings.ToLower(filepath.Base(path))
	relPath := strings.ToLower(filepath.ToSlash(path))

	if base == "gemini.md" || base == "system_instructions.md" || base == "system_instructions" {
		return true, "Gemini context instruction surface", string(model.KindInstruction)
	}
	if strings.Contains(relPath, "/config/") && strings.HasSuffix(base, ".md") {
		return true, "Gemini config surface", string(model.KindInstruction)
	}
	if strings.Contains(relPath, "/skills/") && (base == "skill.md" || strings.HasSuffix(base, ".md")) {
		return true, "Gemini skill extension surface", string(model.KindSkillPackage)
	}
	if base == "mcp.json" {
		return true, "Gemini safe MCP configuration surface", string(model.KindMCPToolDef)
	}
	return false, "", ""
}

func (g *GeminiAdapter) Import(ctx context.Context, machineID string) ([]*model.Artifact, error) {
	v2Envs, err := g.ImportV2(ctx, machineID, nil)
	if err != nil {
		return nil, err
	}
	artifacts := make([]*model.Artifact, 0)
	for _, env := range v2Envs {
		if env.Kind == model.KindSourceRecord {
			continue
		}
		title := "instructions"
		if env.Skill != nil && env.Skill.Name != "" {
			title = env.Skill.Name
		} else if env.Agent != nil && env.Agent.Name != "" {
			title = env.Agent.Name
		} else if env.MCPTool != nil && env.MCPTool.Name != "" {
			title = env.MCPTool.Name
		}
		art := &model.Artifact{
			SchemaVersion: model.SchemaVersionV1,
			Kind:          model.KindInstruction,
			Scope:         env.Scope,
			Title:         title,
			Content:       "",
			ContentType:   "text/markdown",
			Lifecycle:     model.LifecyclePersistent,
			Sensitivity:   model.SensitivityNormal,
			CreatedAt:     env.CreatedAt,
			UpdatedAt:     env.UpdatedAt,
		}
		if env.Memory != nil {
			art.Content = env.Memory.Statement
		} else if env.Skill != nil {
			art.Kind = model.KindSkill
			art.Content = env.Skill.SkillMD
		} else if env.Agent != nil {
			art.Kind = model.KindAgent
			art.Content = env.Agent.Instructions
		} else if env.MCPTool != nil {
			art.Kind = model.KindToolDefinition
			art.Content = env.MCPTool.Command
		}
		art.UpdateFingerprint()
		art.ID = model.GenerateArtifactID(art.Kind, art.Fingerprint)
		artifacts = append(artifacts, art)
	}
	return artifacts, nil
}

func (g *GeminiAdapter) ImportV2(ctx context.Context, machineID string, opCtx *adapter.OperationContext) ([]*model.EnvelopeV2, error) {
	scanRes, err := g.Scan(ctx)
	if err != nil {
		return nil, err
	}

	root, _ := g.resolveRoot()
	envelopes := make([]*model.EnvelopeV2, 0)

	for _, detail := range scanRes.Details {
		if detail.Status != "supported" {
			continue
		}

		data, err := fsutil.ReadFileSafely(detail.Path, fsutil.MaxSupportedFileSize)
		if err != nil {
			continue
		}

		content := string(data)
		hasSecret, _ := security.ScanContentForSecrets(content)
		if hasSecret {
			continue
		}

		scope := model.ScopeGlobal
		projID := ""
		if opCtx != nil && opCtx.WorkspacePath != "" && strings.HasPrefix(detail.Path, opCtx.WorkspacePath) {
			scope = model.ScopeProject
			projID = opCtx.ProjectID
		}

		logicalKey := adapter.ComputeLogicalSourceKey(g.Name(), root, detail.Path)
		srcHash := model.ComputeFingerprint(model.KindInstruction, scope, logicalKey, content, nil)
		sourceRecID := adapter.GenerateStableEntityID("apsr", g.Name(), logicalKey)

		// 1. SourceRecord envelope
		sourceEnv := &model.EnvelopeV2{
			ID:            sourceRecID,
			SchemaVersion: model.SchemaVersionV2,
			Kind:          model.KindSourceRecord,
			Scope:         scope,
			ProjectID:     projID,
			Revision:      1,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Lifecycle:     model.LifecyclePersistent,
			Sensitivity:   model.SensitivityNormal,
			SourceRecord: &model.SourceRecord{
				ID:               sourceRecID,
				Provider:         g.Name(),
				MachineID:        machineID,
				ProjectID:        projID,
				SurfaceType:      detail.Kind,
				LogicalSourceKey: logicalKey,
				LocalPathRef:     detail.Path,
				ContentType:      "text/plain",
				Content:          content,
				SourceHash:       srcHash,
				ObservedAt:       time.Now(),
				Revision:         1,
				Status:           "present",
			},
		}
		sourceEnv.RevisionHash = model.ComputeRevisionHash(sourceEnv)
		if err := sourceEnv.Validate(); err == nil {
			envelopes = append(envelopes, sourceEnv)
		}

		evidence := []model.EvidenceLink{
			{
				SourceRecordID: sourceRecID,
				SourceRevision: 1,
				ContentHash:    srcHash,
			},
		}

		switch detail.Kind {
		case string(model.KindMCPToolDef):
			mcpTools, err := adapter.ParseMCPConfig(content)
			if err == nil {
				for idx, tool := range mcpTools {
					toolID := fmt.Sprintf("%s_%d", adapter.GenerateStableEntityID("apmcp", g.Name(), logicalKey), idx)
					env := &model.EnvelopeV2{
						ID:            toolID,
						SchemaVersion: model.SchemaVersionV2,
						Kind:          model.KindMCPToolDef,
						Scope:         scope,
						ProjectID:     projID,
						Revision:      1,
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
						Lifecycle:     model.LifecyclePersistent,
						Sensitivity:   model.SensitivityNormal,
						MCPTool:       tool,
					}
					env.RevisionHash = model.ComputeRevisionHash(env)
					if err := env.Validate(); err == nil {
						envelopes = append(envelopes, env)
					}
				}
			}
		case string(model.KindSkillPackage):
			skillPkg, err := adapter.ParseSkillPackage(detail.Path, content)
			if err == nil {
				env := &model.EnvelopeV2{
					ID:            adapter.GenerateStableEntityID("aps", g.Name(), logicalKey),
					SchemaVersion: model.SchemaVersionV2,
					Kind:          model.KindSkillPackage,
					Scope:         scope,
					ProjectID:     projID,
					Revision:      1,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
					Lifecycle:     model.LifecyclePersistent,
					Sensitivity:   model.SensitivityNormal,
					Skill:         skillPkg,
				}
				env.RevisionHash = model.ComputeRevisionHash(env)
				if err := env.Validate(); err == nil {
					envelopes = append(envelopes, env)
				}
			}
		default:
			env := &model.EnvelopeV2{
				ID:            adapter.GenerateStableEntityID("api", g.Name(), logicalKey),
				SchemaVersion: model.SchemaVersionV2,
				Kind:          model.KindInstructionV2,
				Scope:         scope,
				ProjectID:     projID,
				Revision:      1,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				Lifecycle:     model.LifecyclePersistent,
				Sensitivity:   model.SensitivityNormal,
				Memory: &model.MemoryPayload{
					Statement:       content,
					Category:        model.CategoryWorkflow,
					Status:          model.MemoryStatusActive,
					Importance:      8,
					Confidence:      1.0,
					Derivation:      model.DerivationImported,
					LastConfirmedAt: time.Now(),
					Evidence:        evidence,
					ReviewState:     "approved",
				},
			}
			env.RevisionHash = model.ComputeRevisionHash(env)
			if err := env.Validate(); err == nil {
				envelopes = append(envelopes, env)
			}
		}
	}

	return envelopes, nil
}

func (g *GeminiAdapter) PlanExportV2(ctx context.Context, manifest *adapter.CompileManifest) (*adapter.ExportPlan, error) {
	root, err := g.resolveRoot()
	if err != nil {
		return nil, err
	}

	plan := &adapter.ExportPlan{
		Provider: g.Name(),
		Items:    make([]*adapter.ExportItem, 0),
	}

	for _, item := range manifest.Items {
		if !item.Included {
			continue
		}

		fileName := strings.ToLower(item.Title)
		fileName = strings.ReplaceAll(fileName, "gemini: ", "")
		fileName = strings.ReplaceAll(fileName, " ", "_") + ".md"
		targetPath := filepath.Join(root, "exported", fileName)

		expItem := &adapter.ExportItem{
			SourceArtifactID: item.ArtifactID,
			TargetPath:       targetPath,
			ProposedContent:  item.Content,
		}

		if existingData, err := os.ReadFile(targetPath); err == nil {
			expItem.CurrentContent = string(existingData)
			if model.NormalizeContent(expItem.CurrentContent) == model.NormalizeContent(item.Content) {
				expItem.Action = adapter.ActionUnchanged
				expItem.DiffSummary = "No changes needed"
			} else {
				expItem.Action = adapter.ActionModify
				expItem.DiffSummary = fmt.Sprintf("Modify %s (%d -> %d bytes)", fileName, len(expItem.CurrentContent), len(item.Content))
			}
		} else {
			expItem.Action = adapter.ActionCreate
			expItem.DiffSummary = fmt.Sprintf("Create %s (%d bytes)", fileName, len(item.Content))
		}

		plan.Items = append(plan.Items, expItem)
	}

	return plan, nil
}

func (g *GeminiAdapter) PlanExport(ctx context.Context, artifacts []*model.Artifact) (*adapter.ExportPlan, error) {
	root, err := g.resolveRoot()
	if err != nil {
		return nil, err
	}

	plan := &adapter.ExportPlan{
		Provider: g.Name(),
		Items:    make([]*adapter.ExportItem, 0),
	}

	for _, art := range artifacts {
		if art.Kind != model.KindInstruction && art.Kind != model.KindMemory && art.Kind != model.KindPreference {
			plan.Items = append(plan.Items, &adapter.ExportItem{
				Action:           adapter.ActionUnsupported,
				SourceArtifactID: art.ID,
				Reason:           fmt.Sprintf("kind %s unsupported by gemini export baseline", art.Kind),
			})
			continue
		}

		fileName := strings.ToLower(art.Title)
		fileName = strings.ReplaceAll(fileName, "gemini: ", "")
		fileName = strings.ReplaceAll(fileName, "codex: ", "")
		fileName = strings.ReplaceAll(fileName, "claude: ", "")
		fileName = strings.ReplaceAll(fileName, " ", "_") + ".md"
		targetPath := filepath.Join(root, "exported", fileName)

		item := &adapter.ExportItem{
			SourceArtifactID: art.ID,
			TargetPath:       targetPath,
			ProposedContent:  art.Content,
		}

		if existingData, err := os.ReadFile(targetPath); err == nil {
			item.CurrentContent = string(existingData)
			if model.NormalizeContent(item.CurrentContent) == model.NormalizeContent(art.Content) {
				item.Action = adapter.ActionUnchanged
				item.DiffSummary = "No changes needed"
			} else {
				item.Action = adapter.ActionModify
				item.DiffSummary = fmt.Sprintf("Modify %s (%d -> %d bytes)", fileName, len(item.CurrentContent), len(art.Content))
			}
		} else {
			item.Action = adapter.ActionCreate
			item.DiffSummary = fmt.Sprintf("Create %s (%d bytes)", fileName, len(art.Content))
		}

		plan.Items = append(plan.Items, item)
	}

	return plan, nil
}

func (g *GeminiAdapter) ApplyExport(ctx context.Context, plan *adapter.ExportPlan) (*adapter.ExportResult, error) {
	res := &adapter.ExportResult{
		Provider:       g.Name(),
		BackupsCreated: make([]string, 0),
		Errors:         make([]string, 0),
	}

	root, err := g.resolveRoot()
	if err != nil {
		return nil, err
	}

	backupDir := filepath.Join(root, "backups")

	for _, item := range plan.Items {
		if item.Action == adapter.ActionUnchanged || item.Action == adapter.ActionUnsupported {
			continue
		}

		if err := fsutil.VerifyNoSymlinkEscape(root, item.TargetPath); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("target path %s escaped root: %v", item.TargetPath, err))
			continue
		}

		if item.Action == adapter.ActionModify {
			if bak, err := fsutil.BackupFile(item.TargetPath, backupDir); err == nil {
				res.BackupsCreated = append(res.BackupsCreated, bak)
			}
		}

		if err := fsutil.WriteFileAtomic(item.TargetPath, []byte(item.ProposedContent), 0600); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("failed writing export target %s: %v", item.TargetPath, err))
			continue
		}

		res.AppliedCount++
	}

	return res, nil
}

func (g *GeminiAdapter) Validate(ctx context.Context) error {
	return nil
}
