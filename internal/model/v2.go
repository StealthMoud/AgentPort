package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

	if e.Scope == ScopeProject && e.ProjectID == "" {
		return fmt.Errorf("%w: scope project requires project_id", ErrInvalidV2Envelope)
	}

	if e.Revision < 1 {
		return fmt.Errorf("%w: revision must be >= 1", ErrInvalidV2Envelope)
	}

	if e.RevisionHash == "" {
		return fmt.Errorf("%w: missing revision_hash", ErrInvalidV2Envelope)
	}

	if e.Sensitivity == SensitivitySecret {
		return ErrSecretArtifactInStorage
	}

	switch e.Kind {
	case KindMemoryV2, KindInstructionV2, KindPreferenceV2, KindProjectContextV2:
		if e.Memory == nil {
			return fmt.Errorf("%w: kind %s requires Memory payload", ErrInvalidV2Envelope, e.Kind)
		}
		if e.Skill != nil || e.Agent != nil || e.MCPTool != nil || e.SourceRecord != nil {
			return fmt.Errorf("%w: kind %s has incompatible extra typed payloads", ErrInvalidV2Envelope, e.Kind)
		}
		if e.Memory.Importance < 1 || e.Memory.Importance > 10 {
			return fmt.Errorf("%w: memory importance must be between 1 and 10", ErrInvalidV2Envelope)
		}
		if e.Memory.Confidence < 0.0 || e.Memory.Confidence > 1.0 {
			return fmt.Errorf("%w: memory confidence must be between 0.0 and 1.0", ErrInvalidV2Envelope)
		}
		switch e.Memory.Status {
		case MemoryStatusActive, MemoryStatusSuperseded, MemoryStatusContested, MemoryStatusArchived, MemoryStatusExpired:
		default:
			return fmt.Errorf("%w: invalid memory status %s", ErrInvalidV2Envelope, e.Memory.Status)
		}
		switch e.Memory.Derivation {
		case DerivationDirect, DerivationSummarized, DerivationInferred, DerivationImported:
		default:
			return fmt.Errorf("%w: invalid memory derivation %s", ErrInvalidV2Envelope, e.Memory.Derivation)
		}
		if e.Memory.ReviewState != "" && e.Memory.ReviewState != "approved" && e.Memory.ReviewState != "pending_review" && e.Memory.ReviewState != "rejected" {
			return fmt.Errorf("%w: invalid review state %s", ErrInvalidV2Envelope, e.Memory.ReviewState)
		}
	case KindSourceRecord:
		if e.SourceRecord == nil {
			return fmt.Errorf("%w: kind source_record requires SourceRecord payload", ErrInvalidV2Envelope)
		}
		if e.Memory != nil || e.Skill != nil || e.Agent != nil || e.MCPTool != nil {
			return fmt.Errorf("%w: kind source_record has incompatible extra typed payloads", ErrInvalidV2Envelope)
		}
	case KindSkillPackage:
		if e.Skill == nil {
			return fmt.Errorf("%w: kind skill requires Skill payload", ErrInvalidV2Envelope)
		}
		if e.Memory != nil || e.SourceRecord != nil || e.Agent != nil || e.MCPTool != nil {
			return fmt.Errorf("%w: kind skill has incompatible extra typed payloads", ErrInvalidV2Envelope)
		}
		if e.Skill.TrustState != SkillTrustUntrusted && e.Skill.TrustState != SkillTrustTrusted && e.Skill.TrustState != SkillTrustLocalOrigin {
			return fmt.Errorf("%w: invalid skill trust state %s", ErrInvalidV2Envelope, e.Skill.TrustState)
		}
	case KindAgentDef:
		if e.Agent == nil {
			return fmt.Errorf("%w: kind agent requires Agent payload", ErrInvalidV2Envelope)
		}
		if e.Memory != nil || e.SourceRecord != nil || e.Skill != nil || e.MCPTool != nil {
			return fmt.Errorf("%w: kind agent has incompatible extra typed payloads", ErrInvalidV2Envelope)
		}
	case KindMCPToolDef:
		if e.MCPTool == nil {
			return fmt.Errorf("%w: kind tool_definition requires MCPTool payload", ErrInvalidV2Envelope)
		}
		if e.Memory != nil || e.SourceRecord != nil || e.Skill != nil || e.Agent != nil {
			return fmt.Errorf("%w: kind tool_definition has incompatible extra typed payloads", ErrInvalidV2Envelope)
		}
	default:
		return fmt.Errorf("%w: unrecognized kind %s", ErrInvalidV2Envelope, e.Kind)
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

type Tombstone struct {
	EntityID             string    `json:"entity_id"`
	DeletedRevision      int       `json:"deleted_revision"`
	DeletedAt            time.Time `json:"deleted_at"`
	OriginMachineID      string    `json:"origin_machine_id"`
	PreviousRevisionHash string    `json:"previous_revision_hash"`
}

// Clone creates a deep copy of EvidenceLink.
func (el EvidenceLink) Clone() EvidenceLink {
	return el
}

// Clone creates a deep copy of MemoryPayload.
func (mp *MemoryPayload) Clone() *MemoryPayload {
	if mp == nil {
		return nil
	}
	cloned := *mp
	if mp.ValidFrom != nil {
		t := *mp.ValidFrom
		cloned.ValidFrom = &t
	}
	if mp.ValidUntil != nil {
		t := *mp.ValidUntil
		cloned.ValidUntil = &t
	}
	if mp.Supersedes != nil {
		cloned.Supersedes = append([]string(nil), mp.Supersedes...)
	}
	if mp.ConflictsWith != nil {
		cloned.ConflictsWith = append([]string(nil), mp.ConflictsWith...)
	}
	if mp.Evidence != nil {
		cloned.Evidence = make([]EvidenceLink, len(mp.Evidence))
		copy(cloned.Evidence, mp.Evidence)
	}
	return &cloned
}

// Clone creates a deep copy of SourceRecord.
func (sr *SourceRecord) Clone() *SourceRecord {
	if sr == nil {
		return nil
	}
	cloned := *sr
	if sr.Files != nil {
		cloned.Files = make(map[string]string, len(sr.Files))
		for k, v := range sr.Files {
			cloned.Files[k] = v
		}
	}
	return &cloned
}

// Clone creates a deep copy of SkillPackage.
func (sp *SkillPackage) Clone() *SkillPackage {
	if sp == nil {
		return nil
	}
	cloned := *sp
	if sp.Scripts != nil {
		cloned.Scripts = make(map[string]string, len(sp.Scripts))
		for k, v := range sp.Scripts {
			cloned.Scripts[k] = v
		}
	}
	if sp.References != nil {
		cloned.References = make(map[string]string, len(sp.References))
		for k, v := range sp.References {
			cloned.References[k] = v
		}
	}
	if sp.Assets != nil {
		cloned.Assets = make(map[string]string, len(sp.Assets))
		for k, v := range sp.Assets {
			cloned.Assets[k] = v
		}
	}
	return &cloned
}

// Clone creates a deep copy of AgentDef.
func (ad *AgentDef) Clone() *AgentDef {
	if ad == nil {
		return nil
	}
	cloned := *ad
	if ad.Capabilities != nil {
		cloned.Capabilities = append([]string(nil), ad.Capabilities...)
	}
	if ad.Skills != nil {
		cloned.Skills = append([]string(nil), ad.Skills...)
	}
	return &cloned
}

// Clone creates a deep copy of MCPToolDef.
func (mt *MCPToolDef) Clone() *MCPToolDef {
	if mt == nil {
		return nil
	}
	cloned := *mt
	if mt.Args != nil {
		cloned.Args = append([]string(nil), mt.Args...)
	}
	if mt.EnvVarNames != nil {
		cloned.EnvVarNames = append([]string(nil), mt.EnvVarNames...)
	}
	return &cloned
}

// Clone creates a complete deep copy of EnvelopeV2.
func (e *EnvelopeV2) Clone() *EnvelopeV2 {
	if e == nil {
		return nil
	}
	cloned := *e
	if e.Tags != nil {
		cloned.Tags = append([]string(nil), e.Tags...)
	}
	if e.Provenance != nil {
		cloned.Provenance = make([]Provenance, len(e.Provenance))
		copy(cloned.Provenance, e.Provenance)
	}
	if e.Metadata != nil {
		cloned.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			cloned.Metadata[k] = v
		}
	}
	cloned.SourceRecord = e.SourceRecord.Clone()
	cloned.Memory = e.Memory.Clone()
	cloned.Skill = e.Skill.Clone()
	cloned.Agent = e.Agent.Clone()
	cloned.MCPTool = e.MCPTool.Clone()
	return &cloned
}

type canonicalKV struct {
	K string `json:"k"`
	V string `json:"v"`
}

type canonicalProvenance struct {
	Provider          string `json:"provider"`
	SourcePath        string `json:"source_path"`
	ImportedAt        string `json:"imported_at,omitempty"`
	SourceFingerprint string `json:"source_fingerprint,omitempty"`
}

type canonicalEvidence struct {
	SourceRecordID string `json:"source_record_id"`
	SourceRevision int    `json:"source_revision"`
	ContentHash    string `json:"content_hash"`
	ExcerptHash    string `json:"excerpt_hash,omitempty"`
}

type canonicalMemoryPayload struct {
	Statement       string              `json:"statement"`
	Category        MemoryCategory      `json:"category"`
	Status          MemoryStatus        `json:"status"`
	Importance      int                 `json:"importance"`
	Confidence      float64             `json:"confidence"`
	Derivation      MemoryDerivation    `json:"derivation"`
	ValidFrom       *string             `json:"valid_from,omitempty"`
	ValidUntil      *string             `json:"valid_until,omitempty"`
	LastConfirmedAt string              `json:"last_confirmed_at"`
	Supersedes      []string            `json:"supersedes,omitempty"`
	ConflictsWith   []string            `json:"conflicts_with,omitempty"`
	Evidence        []canonicalEvidence `json:"evidence,omitempty"`
	ReviewState     string              `json:"review_state"`
}

type canonicalSourceRecordPayload struct {
	Provider         string        `json:"provider"`
	SurfaceType      string        `json:"surface_type"`
	LogicalSourceKey string        `json:"logical_source_key"`
	ContentType      string        `json:"content_type"`
	Content          string        `json:"content"`
	Files            []canonicalKV `json:"files,omitempty"`
	SourceHash       string        `json:"source_hash"`
	Status           string        `json:"status"`
}

type canonicalSkillPayload struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	SkillMD        string          `json:"skill_md"`
	Scripts        []canonicalKV   `json:"scripts,omitempty"`
	References     []canonicalKV   `json:"references,omitempty"`
	Assets         []canonicalKV   `json:"assets,omitempty"`
	TrustState     SkillTrustState `json:"trust_state"`
	HasExecutables bool            `json:"has_executables"`
}

type canonicalAgentPayload struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Instructions        string   `json:"instructions"`
	PreferredModelClass string   `json:"preferred_model_class,omitempty"`
	Capabilities        []string `json:"capabilities,omitempty"`
	Skills              []string `json:"skills,omitempty"`
}

type canonicalMCPPayload struct {
	Name               string   `json:"name"`
	Command            string   `json:"command"`
	Args               []string `json:"args,omitempty"` // PRESERVED ORDER — execution arguments
	URL                string   `json:"url,omitempty"`
	Transport          string   `json:"transport"`
	EnvVarNames        []string `json:"env_var_names,omitempty"`
	WorkingDirPolicy   string   `json:"working_dir_policy,omitempty"`
	RequiresCredential bool     `json:"requires_credential"`
}

type revisionProjection struct {
	Kind        EntityKind            `json:"kind"`
	Scope       Scope                 `json:"scope"`
	ProjectID   string                `json:"project_id,omitempty"`
	Lifecycle   Lifecycle             `json:"lifecycle"`
	Sensitivity Sensitivity           `json:"sensitivity"`
	Tags        []string              `json:"tags,omitempty"`
	Provenance  []canonicalProvenance `json:"provenance,omitempty"`
	Metadata    []canonicalKV         `json:"metadata,omitempty"`
	Payload     any                   `json:"payload"`
}

func mapToCanonicalKV(m map[string]string) []canonicalKV {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]canonicalKV, len(keys))
	for i, k := range keys {
		res[i] = canonicalKV{K: k, V: m[k]}
	}
	return res
}

func formatTimeNano(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimeNanoPtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func canonicalizeEvidence(links []EvidenceLink) []canonicalEvidence {
	if len(links) == 0 {
		return nil
	}
	res := make([]canonicalEvidence, len(links))
	for i, link := range links {
		res[i] = canonicalEvidence{
			SourceRecordID: link.SourceRecordID,
			SourceRevision: link.SourceRevision,
			ContentHash:    link.ContentHash,
			ExcerptHash:    link.ExcerptHash,
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].SourceRecordID != res[j].SourceRecordID {
			return res[i].SourceRecordID < res[j].SourceRecordID
		}
		if res[i].SourceRevision != res[j].SourceRevision {
			return res[i].SourceRevision < res[j].SourceRevision
		}
		if res[i].ContentHash != res[j].ContentHash {
			return res[i].ContentHash < res[j].ContentHash
		}
		return res[i].ExcerptHash < res[j].ExcerptHash
	})
	return res
}

func canonicalizeProvenance(provs []Provenance) []canonicalProvenance {
	if len(provs) == 0 {
		return nil
	}
	res := make([]canonicalProvenance, len(provs))
	for i, p := range provs {
		res[i] = canonicalProvenance{
			Provider:          p.Provider,
			SourcePath:        p.SourcePath,
			ImportedAt:        formatTimeNano(p.ImportedAt),
			SourceFingerprint: p.SourceFingerprint,
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Provider != res[j].Provider {
			return res[i].Provider < res[j].Provider
		}
		if res[i].SourcePath != res[j].SourcePath {
			return res[i].SourcePath < res[j].SourcePath
		}
		if res[i].ImportedAt != res[j].ImportedAt {
			return res[i].ImportedAt < res[j].ImportedAt
		}
		return res[i].SourceFingerprint < res[j].SourceFingerprint
	})
	return res
}

// ComputeRevisionHash calculates a canonical, deterministic revision hash for a V2 entity.
//
// Inclusion policy:
//   - All portable semantic state that changes the meaning of the entity is included.
//   - Portable Envelope.Provenance is included (canonicalized by tuple: Provider|SourcePath|ImportedAt|SourceFingerprint).
//   - Non-semantic / machine-local fields are excluded:
//     MachineID (provenance only), LocalPathRef (local filesystem), ObservedAt (observation
//     timestamp), Revision counter & PreviousRevision (monotonic counter / ancestry — not current content).
//
// Collection ordering:
//   - Unordered sets (Tags, Supersedes, ConflictsWith, EnvVarNames, Capabilities, Skills, Provenance, Evidence, map keys)
//     are sorted before hashing so that insertion order does not affect the hash.
//   - IMPORTANT: MCPToolDef.Args are NOT sorted. Command arguments are ordered execution arguments.
func ComputeRevisionHash(env *EnvelopeV2) string {
	sortedTags := append([]string(nil), env.Tags...)
	sort.Strings(sortedTags)

	proj := revisionProjection{
		Kind:        env.Kind,
		Scope:       env.Scope,
		ProjectID:   env.ProjectID,
		Lifecycle:   env.Lifecycle,
		Sensitivity: env.Sensitivity,
		Tags:        sortedTags,
		Provenance:  canonicalizeProvenance(env.Provenance),
		Metadata:    mapToCanonicalKV(env.Metadata),
	}

	switch env.Kind {
	case KindMemoryV2, KindInstructionV2, KindPreferenceV2, KindProjectContextV2:
		if env.Memory != nil {
			m := env.Memory
			supersedes := append([]string(nil), m.Supersedes...)
			sort.Strings(supersedes)
			conflictsWith := append([]string(nil), m.ConflictsWith...)
			sort.Strings(conflictsWith)

			proj.Payload = canonicalMemoryPayload{
				Statement:       m.Statement,
				Category:        m.Category,
				Status:          m.Status,
				Importance:      m.Importance,
				Confidence:      m.Confidence,
				Derivation:      m.Derivation,
				ValidFrom:       formatTimeNanoPtr(m.ValidFrom),
				ValidUntil:      formatTimeNanoPtr(m.ValidUntil),
				LastConfirmedAt: formatTimeNano(m.LastConfirmedAt),
				Supersedes:      supersedes,
				ConflictsWith:   conflictsWith,
				Evidence:        canonicalizeEvidence(m.Evidence),
				ReviewState:     m.ReviewState,
			}
		}

	case KindSourceRecord:
		if env.SourceRecord != nil {
			sr := env.SourceRecord
			proj.Payload = canonicalSourceRecordPayload{
				Provider:         sr.Provider,
				SurfaceType:      sr.SurfaceType,
				LogicalSourceKey: sr.LogicalSourceKey,
				ContentType:      sr.ContentType,
				Content:          sr.Content,
				Files:            mapToCanonicalKV(sr.Files),
				SourceHash:       sr.SourceHash,
				Status:           sr.Status,
			}
		}

	case KindSkillPackage:
		if env.Skill != nil {
			sk := env.Skill
			proj.Payload = canonicalSkillPayload{
				Name:           sk.Name,
				Description:    sk.Description,
				SkillMD:        sk.SkillMD,
				Scripts:        mapToCanonicalKV(sk.Scripts),
				References:     mapToCanonicalKV(sk.References),
				Assets:         mapToCanonicalKV(sk.Assets),
				TrustState:     sk.TrustState,
				HasExecutables: sk.HasExecutables,
			}
		}

	case KindAgentDef:
		if env.Agent != nil {
			ag := env.Agent
			caps := append([]string(nil), ag.Capabilities...)
			sort.Strings(caps)
			skills := append([]string(nil), ag.Skills...)
			sort.Strings(skills)

			proj.Payload = canonicalAgentPayload{
				Name:                ag.Name,
				Description:         ag.Description,
				Instructions:        ag.Instructions,
				PreferredModelClass: ag.PreferredModelClass,
				Capabilities:        caps,
				Skills:              skills,
			}
		}

	case KindMCPToolDef:
		if env.MCPTool != nil {
			mcp := env.MCPTool
			envVars := append([]string(nil), mcp.EnvVarNames...)
			sort.Strings(envVars)

			proj.Payload = canonicalMCPPayload{
				Name:               mcp.Name,
				Command:            mcp.Command,
				Args:               mcp.Args, // PRESERVED ORDER — command line arguments
				URL:                mcp.URL,
				Transport:          mcp.Transport,
				EnvVarNames:        envVars,
				WorkingDirPolicy:   mcp.WorkingDirPolicy,
				RequiresCredential: mcp.RequiresCredential,
			}
		}
	}

	data, _ := json.Marshal(proj)
	return ComputeFingerprint(KindMemory, ScopeGlobal, "v2_revision", string(data), nil)
}

// ComputeV2StateRoot calculates a deterministic state root from V2 envelopes sorted by ID.
func ComputeV2StateRoot(entities []*EnvelopeV2) string {
	sorted := make([]*EnvelopeV2, len(entities))
	copy(sorted, entities)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	var total string
	for _, env := range sorted {
		total += fmt.Sprintf("%s:%d:%s|", env.ID, env.Revision, env.RevisionHash)
	}

	return ComputeFingerprint(KindMemory, ScopeGlobal, "vault_v2_state_root", total, nil)
}
