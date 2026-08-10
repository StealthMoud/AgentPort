package model

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
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

// ComputeRevisionHash calculates a canonical, deterministic revision hash for a V2 entity.
//
// Inclusion policy:
//   - All portable semantic state that changes the meaning of the entity is included.
//   - Non-semantic / machine-local fields are excluded:
//     MachineID (provenance only), LocalPathRef (local filesystem), ObservedAt (observation
//     timestamp), Revision counter (monotonic counter — not semantic content).
//
// Collection ordering:
//   - Unordered sets (Tags, Supersedes, ConflictsWith, EnvVarNames, map keys) are sorted
//     before hashing so that insertion order does not affect the hash.
//   - IMPORTANT: MCPToolDef.Args are NOT sorted. Command arguments are ordered and
//     changing their order is a semantic change.
func ComputeRevisionHash(env *EnvelopeV2) string {
	var payloadStr string

	switch env.Kind {
	case KindMemoryV2, KindInstructionV2, KindPreferenceV2, KindProjectContextV2:
		if env.Memory != nil {
			m := env.Memory

			// Canonicalize validity windows as RFC3339 UTC strings (empty string if nil).
			validFromStr := ""
			if m.ValidFrom != nil {
				validFromStr = m.ValidFrom.UTC().Format("2006-01-02T15:04:05Z")
			}
			validUntilStr := ""
			if m.ValidUntil != nil {
				validUntilStr = m.ValidUntil.UTC().Format("2006-01-02T15:04:05Z")
			}
			lastConfirmedStr := m.LastConfirmedAt.UTC().Format("2006-01-02T15:04:05Z")

			// Sort unordered set fields to guarantee determinism.
			supersedes := append([]string(nil), m.Supersedes...)
			sort.Strings(supersedes)
			conflictsWith := append([]string(nil), m.ConflictsWith...)
			sort.Strings(conflictsWith)

			// Canonicalize Evidence: sort by SourceRecordID then SourceRevision,
			// then encode each link as a fixed-format string.
			type evidenceKey struct {
				id  string
				rev int
			}
			type evidenceEntry struct {
				k evidenceKey
				v EvidenceLink
			}
			evEntries := make([]evidenceEntry, len(m.Evidence))
			for i, ev := range m.Evidence {
				evEntries[i] = evidenceEntry{k: evidenceKey{ev.SourceRecordID, ev.SourceRevision}, v: ev}
			}
			sort.Slice(evEntries, func(i, j int) bool {
				ki, kj := evEntries[i].k, evEntries[j].k
				if ki.id != kj.id {
					return ki.id < kj.id
				}
				return ki.rev < kj.rev
			})
			evidenceParts := make([]string, len(evEntries))
			for i, ee := range evEntries {
				evidenceParts[i] = fmt.Sprintf("%s|%d|%s|%s",
					ee.v.SourceRecordID, ee.v.SourceRevision, ee.v.ContentHash, ee.v.ExcerptHash)
			}

			payloadStr = fmt.Sprintf(
				"stmt:%s|cat:%s|stat:%s|imp:%d|conf:%.4f|deriv:%s|"+
					"validfrom:%s|validuntil:%s|lastconfirmed:%s|"+
					"supersedes:%s|conflicts:%s|evidence:%s|revst:%s",
				m.Statement, m.Category, m.Status,
				m.Importance, m.Confidence, m.Derivation,
				validFromStr, validUntilStr, lastConfirmedStr,
				strings.Join(supersedes, ","),
				strings.Join(conflictsWith, ","),
				strings.Join(evidenceParts, ";"),
				m.ReviewState,
			)
		}

	case KindSourceRecord:
		if env.SourceRecord != nil {
			sr := env.SourceRecord
			// Include all portable semantic fields.
			// Excluded: MachineID (local provenance), LocalPathRef (local filesystem path),
			//           ObservedAt (observation metadata, not content).
			var fileKeys []string
			for k := range sr.Files {
				fileKeys = append(fileKeys, k)
			}
			sort.Strings(fileKeys)
			fileParts := make([]string, len(fileKeys))
			for i, k := range fileKeys {
				fileParts[i] = k + "=" + sr.Files[k]
			}
			payloadStr = fmt.Sprintf(
				"prov:%s|surf:%s|key:%s|ctype:%s|content:%s|files:%s|hash:%s|stat:%s|rev:%d|prevrev:%s",
				sr.Provider, sr.SurfaceType, sr.LogicalSourceKey,
				sr.ContentType, sr.Content,
				strings.Join(fileParts, ";"),
				sr.SourceHash, sr.Status, sr.Revision, sr.PreviousRevision,
			)
		}

	case KindSkillPackage:
		if env.Skill != nil {
			var scriptKeys, refKeys, assetKeys []string
			for k := range env.Skill.Scripts {
				scriptKeys = append(scriptKeys, k)
			}
			for k := range env.Skill.References {
				refKeys = append(refKeys, k)
			}
			for k := range env.Skill.Assets {
				assetKeys = append(assetKeys, k)
			}
			sort.Strings(scriptKeys)
			sort.Strings(refKeys)
			sort.Strings(assetKeys)
			scriptParts := make([]string, len(scriptKeys))
			refParts := make([]string, len(refKeys))
			assetParts := make([]string, len(assetKeys))
			for i, k := range scriptKeys {
				scriptParts[i] = k + "=" + env.Skill.Scripts[k]
			}
			for i, k := range refKeys {
				refParts[i] = k + "=" + env.Skill.References[k]
			}
			for i, k := range assetKeys {
				assetParts[i] = k + "=" + env.Skill.Assets[k]
			}
			payloadStr = fmt.Sprintf("name:%s|desc:%s|md:%s|trust:%s|exec:%v|scripts:%s|refs:%s|assets:%s",
				env.Skill.Name, env.Skill.Description, env.Skill.SkillMD,
				env.Skill.TrustState, env.Skill.HasExecutables,
				strings.Join(scriptParts, ";"),
				strings.Join(refParts, ";"),
				strings.Join(assetParts, ";"))
		}

	case KindAgentDef:
		if env.Agent != nil {
			caps := append([]string(nil), env.Agent.Capabilities...)
			skills := append([]string(nil), env.Agent.Skills...)
			sort.Strings(caps)
			sort.Strings(skills)
			payloadStr = fmt.Sprintf("name:%s|desc:%s|inst:%s|model:%s|caps:%s|skills:%s",
				env.Agent.Name, env.Agent.Description, env.Agent.Instructions,
				env.Agent.PreferredModelClass,
				strings.Join(caps, ","), strings.Join(skills, ","))
		}

	case KindMCPToolDef:
		if env.MCPTool != nil {
			// Args order is PRESERVED — these are ordered command-line arguments.
			// Changing arg order is a semantic change and must change the hash.
			envVars := append([]string(nil), env.MCPTool.EnvVarNames...)
			sort.Strings(envVars) // env var names are a set; order is not significant
			payloadStr = fmt.Sprintf(
				"name:%s|cmd:%s|args:%s|url:%s|trans:%s|envvars:%s|wdpol:%s|reqcred:%v",
				env.MCPTool.Name, env.MCPTool.Command,
				strings.Join(env.MCPTool.Args, "\x00"), // use NUL separator — args may contain commas
				env.MCPTool.URL, env.MCPTool.Transport,
				strings.Join(envVars, ","),
				env.MCPTool.WorkingDirPolicy,
				env.MCPTool.RequiresCredential,
			)
		}
	}

	metaStr := ""
	if len(env.Metadata) > 0 {
		var keys []string
		for k := range env.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			metaStr += fmt.Sprintf("%s=%s;", k, env.Metadata[k])
		}
	}

	tagsStr := ""
	if len(env.Tags) > 0 {
		sortedTags := append([]string(nil), env.Tags...)
		sort.Strings(sortedTags)
		tagsStr = strings.Join(sortedTags, ",")
	}

	// NOTE: Revision (monotonic counter) is intentionally excluded — it is not semantic
	// state. Two entities with different revision counters but identical content have the
	// same semantic meaning and should produce the same RevisionHash, which lets the
	// reconciler detect true no-ops even across sync roundtrips.
	combined := fmt.Sprintf("kind:%s|scope:%s|proj:%s|sens:%s|life:%s|tags:%s|meta:%s|payload:%s",
		env.Kind, env.Scope, env.ProjectID, env.Sensitivity, env.Lifecycle, tagsStr, metaStr, payloadStr)

	return ComputeFingerprint(KindMemory, ScopeGlobal, "v2_revision", combined, nil)
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
