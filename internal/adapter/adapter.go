package adapter

import (
	"context"

	"github.com/StealthMoud/AgentPort/internal/model"
)

type ExportAction string

const (
	ActionCreate      ExportAction = "create"
	ActionModify      ExportAction = "modify"
	ActionUnchanged   ExportAction = "unchanged"
	ActionConflict    ExportAction = "conflict"
	ActionUnsupported ExportAction = "unsupported"
)

type DetectResult struct {
	Provider string `json:"provider"`
	Detected bool   `json:"detected"`
	RootPath string `json:"root_path"`
	Message  string `json:"message"`
}

type ScanDetail struct {
	Path   string `json:"path"`
	Status string `json:"status"` // "supported", "ignored", "rejected"
	Reason string `json:"reason"`
	Kind   string `json:"kind,omitempty"`
}

type ScanResult struct {
	Provider           string       `json:"provider"`
	SupportedArtifacts int          `json:"supported_artifacts"`
	UnsupportedIgnored int          `json:"unsupported_ignored"`
	RejectedBySecurity int          `json:"rejected_by_security"`
	Details            []ScanDetail `json:"details"`
}

type ExportItem struct {
	Action           ExportAction `json:"action"`
	SourceArtifactID string       `json:"source_artifact_id"`
	TargetPath       string       `json:"target_path"`
	ProposedContent  string       `json:"proposed_content"`
	CurrentContent   string       `json:"current_content"`
	DiffSummary      string       `json:"diff_summary"`
	Reason           string       `json:"reason,omitempty"`
}

type ExportPlan struct {
	Provider string        `json:"provider"`
	Items    []*ExportItem `json:"items"`
}

type ExportResult struct {
	Provider       string   `json:"provider"`
	AppliedCount   int      `json:"applied_count"`
	BackupsCreated []string `json:"backups_created"`
	Errors         []string `json:"errors"`
}

type FeatureSupport string

const (
	SupportFull        FeatureSupport = "full"
	SupportPartial     FeatureSupport = "partial"
	SupportImportOnly  FeatureSupport = "import-only"
	SupportExportOnly  FeatureSupport = "export-only"
	SupportUnsupported FeatureSupport = "unsupported"
)

type Capabilities struct {
	Instructions FeatureSupport `json:"instructions"`
	Memory       FeatureSupport `json:"memory"`
	Skills       FeatureSupport `json:"skills"`
	Agents       FeatureSupport `json:"agents"`
	MCP          FeatureSupport `json:"mcp"`
	ProjectRules FeatureSupport `json:"project_rules"`
}

type OperationContext struct {
	WorkspacePath string      `json:"workspace_path"`
	ProjectID     string      `json:"project_id"`
	Scope         model.Scope `json:"scope"`
}

type Adapter interface {
	Name() string
	Detect(ctx context.Context) (*DetectResult, error)
	Capabilities() Capabilities
	Scan(ctx context.Context) (*ScanResult, error)
	Import(ctx context.Context, machineID string) ([]*model.Artifact, error)
	ImportV2(ctx context.Context, machineID string, opCtx *OperationContext) ([]*model.EnvelopeV2, error)
	PlanExport(ctx context.Context, artifacts []*model.Artifact) (*ExportPlan, error)
	ApplyExport(ctx context.Context, plan *ExportPlan) (*ExportResult, error)
	Validate(ctx context.Context) error
}
