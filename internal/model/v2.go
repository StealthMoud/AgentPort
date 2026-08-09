package model

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const SchemaVersionV2 = "2"

// EntityKind defines the primary entity types in Schema V2.
type EntityKind string

const (
	KindSourceRecord     EntityKind = "source_record"
	KindMemoryV2         EntityKind = "memory"
	KindInstructionV2    EntityKind = "instruction"
	KindPreferenceV2     EntityKind = "preference"
	KindSkillPackage     EntityKind = "skill"
	KindAgentDef         EntityKind = "agent"
	KindMCPToolDef       EntityKind = "tool_definition"
	KindProjectContextV2 EntityKind = "project_context"
)

var (
	ErrInvalidV2Envelope = errors.New("invalid schema v2 envelope")
)

// GenerateEntityID generates a stable random V2 canonical ID with a prefix (e.g. apm_..., aps_..., api_...).
func GenerateEntityID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// EnvelopeV2 represents the generic canonical container for all V2 entities.
type EnvelopeV2 struct {
	ID            string            `json:"id"`
	SchemaVersion string            `json:"schema_version"`
	Kind          EntityKind        `json:"kind"`
	Scope         Scope             `json:"scope"`
	ProjectID     string            `json:"project_id,omitempty"`
	Revision      int               `json:"revision"`
	RevisionHash  string            `json:"revision_hash"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Lifecycle     Lifecycle         `json:"lifecycle"`
	Sensitivity   Sensitivity       `json:"sensitivity"`
	Tags          []string          `json:"tags,omitempty"`
	Provenance    []Provenance      `json:"provenance"`
	Metadata      map[string]string `json:"metadata,omitempty"`

	// Typed Payloads
	SourceRecord *SourceRecord  `json:"source_record,omitempty"`
	Memory       *MemoryPayload `json:"memory_payload,omitempty"`
	Skill        *SkillPackage  `json:"skill_package,omitempty"`
	Agent        *AgentDef      `json:"agent_def,omitempty"`
	MCPTool      *MCPToolDef    `json:"mcp_tool_def,omitempty"`
}

// Validate checks EnvelopeV2 invariant rules.
func (e *EnvelopeV2) Validate() error {
	if e.SchemaVersion != SchemaVersionV2 {
		return fmt.Errorf("%w: got %s, want %s", ErrUnsupportedSchema, e.SchemaVersion, SchemaVersionV2)
	}

	if e.ID == "" {
		return fmt.Errorf("%w: missing ID", ErrInvalidV2Envelope)
	}

	if !e.Scope.IsValid() {
		return fmt.Errorf("%w: invalid scope %s", ErrInvalidV2Envelope, e.Scope)
	}

	if e.Sensitivity == SensitivitySecret {
		return ErrSecretArtifactInStorage
	}

	return nil
}

// SourceRecord captures observed provider source file evidence.
type SourceRecord struct {
	ID               string            `json:"id"`
	Provider         string            `json:"provider"`
	MachineID        string            `json:"machine_id"`
	ProjectID        string            `json:"project_id,omitempty"`
	SurfaceType      string            `json:"surface_type"` // e.g. "instructions", "rule", "auto_memory"
	LogicalSourceKey string            `json:"logical_source_key"`
	LocalPathRef     string            `json:"local_path_ref,omitempty"` // local-only metadata
	ContentType      string            `json:"content_type"`
	Content          string            `json:"content"`
	Files            map[string]string `json:"files,omitempty"`
	SourceHash       string            `json:"source_hash"`
	ObservedAt       time.Time         `json:"observed_at"`
	Revision         int               `json:"revision"`
	PreviousRevision string            `json:"previous_revision,omitempty"`
	Status           string            `json:"status"` // "present", "missing", "deleted", "superseded"
}

type MemoryCategory string

const (
	CategoryIdentity      MemoryCategory = "identity"
	CategoryPreference    MemoryCategory = "preference"
	CategoryWorkflow      MemoryCategory = "workflow"
	CategoryProjectFact   MemoryCategory = "project_fact"
	CategoryDecision      MemoryCategory = "decision"
	CategoryConstraint    MemoryCategory = "constraint"
	CategoryHistorical    MemoryCategory = "historical"
	CategoryTemporary     MemoryCategory = "temporary"
	CategoryTooling       MemoryCategory = "tooling"
	CategoryCommunication MemoryCategory = "communication"
	CategoryUncategorized MemoryCategory = "uncategorized"
)

type MemoryStatus string

const (
	MemoryStatusActive     MemoryStatus = "active"
	MemoryStatusSuperseded MemoryStatus = "superseded"
	MemoryStatusContested  MemoryStatus = "contested"
	MemoryStatusArchived   MemoryStatus = "archived"
	MemoryStatusExpired    MemoryStatus = "expired"
)

type MemoryDerivation string

const (
	DerivationDirect     MemoryDerivation = "direct"
	DerivationSummarized MemoryDerivation = "summarized"
	DerivationInferred   MemoryDerivation = "inferred"
	DerivationImported   MemoryDerivation = "imported"
)

type EvidenceLink struct {
	SourceRecordID string `json:"source_record_id"`
	SourceRevision int    `json:"source_revision"`
	ContentHash    string `json:"content_hash"`
	ExcerptHash    string `json:"excerpt_hash,omitempty"`
}

type MemoryPayload struct {
	Statement       string           `json:"statement"`
	Category        MemoryCategory   `json:"category"`
	Status          MemoryStatus     `json:"status"`
	Importance      int              `json:"importance"` // 1 to 10
	Confidence      float64          `json:"confidence"` // 0.0 to 1.0
	Derivation      MemoryDerivation `json:"derivation"`
	ValidFrom       *time.Time       `json:"valid_from,omitempty"`
	ValidUntil      *time.Time       `json:"valid_until,omitempty"`
	LastConfirmedAt time.Time        `json:"last_confirmed_at"`
	Supersedes      []string         `json:"supersedes,omitempty"`
	ConflictsWith   []string         `json:"conflicts_with,omitempty"`
	Evidence        []EvidenceLink   `json:"evidence,omitempty"`
	ReviewState     string           `json:"review_state"` // "approved", "pending_review", "rejected"
}

type SkillTrustState string

const (
	SkillTrustUntrusted   SkillTrustState = "untrusted"
	SkillTrustTrusted     SkillTrustState = "trusted"
	SkillTrustLocalOrigin SkillTrustState = "local-origin"
)

type SkillPackage struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	SkillMD        string            `json:"skill_md"`
	Scripts        map[string]string `json:"scripts,omitempty"`
	References     map[string]string `json:"references,omitempty"`
	Assets         map[string]string `json:"assets,omitempty"`
	TrustState     SkillTrustState   `json:"trust_state"`
	HasExecutables bool              `json:"has_executables"`
}

type AgentDef struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Instructions        string   `json:"instructions"`
	PreferredModelClass string   `json:"preferred_model_class,omitempty"`
	Capabilities        []string `json:"capabilities,omitempty"`
	Skills              []string `json:"skills,omitempty"`
}

type MCPToolDef struct {
	Name               string   `json:"name"`
	Command            string   `json:"command"`
	Args               []string `json:"args,omitempty"`
	URL                string   `json:"url,omitempty"`
	Transport          string   `json:"transport"` // e.g. "stdio", "sse", "http"
	EnvVarNames        []string `json:"env_var_names,omitempty"`
	WorkingDirPolicy   string   `json:"working_dir_policy,omitempty"`
	RequiresCredential bool     `json:"requires_credential"`
}
