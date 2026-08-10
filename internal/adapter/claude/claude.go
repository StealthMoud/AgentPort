package claude

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

type ClaudeAdapter struct {
	customRoot string
}

func New(customRoot string) *ClaudeAdapter {
	return &ClaudeAdapter{customRoot: customRoot}
}

func (c *ClaudeAdapter) Name() string {
	return "claude"
}

func (c *ClaudeAdapter) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{
		Instructions: adapter.SupportFull,
		Memory:       adapter.SupportFull,
		Skills:       adapter.SupportFull,
		Agents:       adapter.SupportFull,
		MCP:          adapter.SupportPartial,
		ProjectRules: adapter.SupportFull,
	}
}

func (c *ClaudeAdapter) resolveRoot() (string, error) {
	if c.customRoot != "" {
		return c.customRoot, nil
	}
	if env := os.Getenv("CLAUDE_HOME"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude"), nil
}

func (c *ClaudeAdapter) Detect(ctx context.Context) (*adapter.DetectResult, error) {
	root, err := c.resolveRoot()
	if err != nil {
		return &adapter.DetectResult{Provider: c.Name(), Detected: false, Message: err.Error()}, nil
	}

	info, err := os.Stat(root)
	if err == nil && info.IsDir() {
		return &adapter.DetectResult{
			Provider: c.Name(),
			Detected: true,
			RootPath: root,
			Message:  "Claude Code directory detected",
		}, nil
	}

	return &adapter.DetectResult{
		Provider: c.Name(),
		Detected: false,
		RootPath: root,
		Message:  "Claude Code installation not found",
	}, nil
}

func (c *ClaudeAdapter) Scan(ctx context.Context) (*adapter.ScanResult, error) {
	root, _ := c.resolveRoot()
	res := &adapter.ScanResult{
		Provider: c.Name(),
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

		isSurface, reason, kind := isExplicitClaudeSurface(path)
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

func isExplicitClaudeSurface(path string) (bool, string, string) {
	base := strings.ToLower(filepath.Base(path))
	relPath := strings.ToLower(filepath.ToSlash(path))

	if base == "claude.md" {
		return true, "Claude CLAUDE.md instruction surface", string(model.KindInstruction)
	}
	if strings.Contains(relPath, "/rules/") && strings.HasSuffix(base, ".md") {
		return true, "Claude project rule surface", string(model.KindInstruction)
	}
	if strings.Contains(relPath, "/memory/") && strings.HasSuffix(base, ".md") {
		return true, "Claude auto-memory surface", string(model.KindMemory)
	}
	if strings.Contains(relPath, "/skills/") && (base == "skill.md" || base == "skill.json" || strings.HasSuffix(base, ".md")) {
		return true, "Claude skill surface", string(model.KindSkillPackage)
	}
	if strings.Contains(relPath, "/agents/") && (strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".md")) {
		return true, "Claude agent definition surface", string(model.KindAgentDef)
	}
	if base == ".mcp.json" || base == "mcp.json" {
		return true, "Claude safe MCP configuration surface", string(model.KindMCPToolDef)
	}
	return false, "", ""
}

func (c *ClaudeAdapter) Import(ctx context.Context, machineID string) ([]*model.Artifact, error) {
	v2Envs, err := c.ImportV2(ctx, machineID, nil)
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

func (c *ClaudeAdapter) ImportV2(ctx context.Context, machineID string, opCtx *adapter.OperationContext) ([]*model.EnvelopeV2, error) {
	scanRes, err := c.Scan(ctx)
	if err != nil {
		return nil, err
	}

	root, _ := c.resolveRoot()
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

		logicalKey := adapter.ComputeLogicalSourceKey(c.Name(), root, detail.Path)
		srcHash := model.ComputeFingerprint(model.KindInstruction, scope, logicalKey, content, nil)
		sourceRecID := adapter.GenerateStableEntityID("apsr", c.Name(), logicalKey)

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
				Provider:         c.Name(),
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
					toolID := fmt.Sprintf("%s_%d", adapter.GenerateStableEntityID("apmcp", c.Name(), logicalKey), idx)
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
					ID:            adapter.GenerateStableEntityID("aps", c.Name(), logicalKey),
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
		case string(model.KindAgentDef):
			agentDef, err := adapter.ParseAgentDef(detail.Path, content)
			if err == nil {
				env := &model.EnvelopeV2{
					ID:            adapter.GenerateStableEntityID("apa", c.Name(), logicalKey),
					SchemaVersion: model.SchemaVersionV2,
					Kind:          model.KindAgentDef,
					Scope:         scope,
					ProjectID:     projID,
					Revision:      1,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
					Lifecycle:     model.LifecyclePersistent,
					Sensitivity:   model.SensitivityNormal,
					Agent:         agentDef,
				}
				env.RevisionHash = model.ComputeRevisionHash(env)
				if err := env.Validate(); err == nil {
					envelopes = append(envelopes, env)
				}
			}
		default:
			kind := model.KindInstructionV2
			if strings.Contains(logicalKey, "memory") {
				kind = model.KindMemoryV2
			}
			env := &model.EnvelopeV2{
				ID:            adapter.GenerateStableEntityID("api", c.Name(), logicalKey),
				SchemaVersion: model.SchemaVersionV2,
				Kind:          kind,
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

func (c *ClaudeAdapter) PlanExportV2(ctx context.Context, manifest *adapter.CompileManifest) (*adapter.ExportPlan, error) {
	root, err := c.resolveRoot()
	if err != nil {
		return nil, err
	}

	plan := &adapter.ExportPlan{
		Provider: c.Name(),
		Items:    make([]*adapter.ExportItem, 0),
	}

	for _, item := range manifest.Items {
		if !item.Included {
			continue
		}

		fileName := strings.ToLower(item.Title)
		fileName = strings.ReplaceAll(fileName, "claude: ", "")
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

func (c *ClaudeAdapter) PlanExport(ctx context.Context, artifacts []*model.Artifact) (*adapter.ExportPlan, error) {
	root, err := c.resolveRoot()
	if err != nil {
		return nil, err
	}

	plan := &adapter.ExportPlan{
		Provider: c.Name(),
		Items:    make([]*adapter.ExportItem, 0),
	}

	for _, art := range artifacts {
		if art.Kind != model.KindInstruction && art.Kind != model.KindMemory && art.Kind != model.KindPreference {
			plan.Items = append(plan.Items, &adapter.ExportItem{
				Action:           adapter.ActionUnsupported,
				SourceArtifactID: art.ID,
				Reason:           fmt.Sprintf("kind %s unsupported by claude export baseline", art.Kind),
			})
			continue
		}

		fileName := strings.ToLower(art.Title)
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

func (c *ClaudeAdapter) ApplyExport(ctx context.Context, plan *adapter.ExportPlan) (*adapter.ExportResult, error) {
	res := &adapter.ExportResult{
		Provider:       c.Name(),
		BackupsCreated: make([]string, 0),
		Errors:         make([]string, 0),
	}

	root, err := c.resolveRoot()
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

func (c *ClaudeAdapter) Validate(ctx context.Context) error {
	return nil
}
