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

		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(filepath.Base(path))

		if ext == ".md" || base == "claude.md" || base == "instructions" {
			res.SupportedArtifacts++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "supported",
				Reason: "portable instruction / memory surface",
				Kind:   string(model.KindInstruction),
			})
		} else {
			res.UnsupportedIgnored++
			res.Details = append(res.Details, adapter.ScanDetail{
				Path:   path,
				Status: "ignored",
				Reason: "unsupported file format",
			})
		}

		return nil
	})

	return res, nil
}

func (c *ClaudeAdapter) Import(ctx context.Context, machineID string) ([]*model.Artifact, error) {
	scanRes, err := c.Scan(ctx)
	if err != nil {
		return nil, err
	}

	artifacts := make([]*model.Artifact, 0)

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

		title := strings.TrimSuffix(filepath.Base(detail.Path), filepath.Ext(detail.Path))
		kind := model.KindInstruction
		if strings.Contains(strings.ToLower(title), "memory") {
			kind = model.KindMemory
		}

		art := &model.Artifact{
			SchemaVersion: model.SchemaVersionV1,
			Kind:          kind,
			Scope:         model.ScopeGlobal,
			Title:         title,
			Content:       content,
			ContentType:   "text/markdown",
			Lifecycle:     model.LifecyclePersistent,
			Sensitivity:   model.SensitivityNormal,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Provenance: []model.Provenance{
				{
					Provider:          c.Name(),
					MachineID:         machineID,
					SourcePath:        detail.Path,
					ImportedAt:        time.Now(),
					SourceFingerprint: model.ComputeFingerprint(kind, model.ScopeGlobal, title, content, nil),
				},
			},
		}

		art.UpdateFingerprint()
		art.ID = model.GenerateArtifactID(art.Kind, art.Fingerprint)

		artifacts = append(artifacts, art)
	}

	return artifacts, nil
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
