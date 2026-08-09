package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersionV1 = "1"

type Kind string

const (
	KindInstruction    Kind = "instruction"
	KindMemory         Kind = "memory"
	KindPreference     Kind = "preference"
	KindSkill          Kind = "skill"
	KindAgent          Kind = "agent"
	KindProjectContext Kind = "project_context"
	KindToolDefinition Kind = "tool_definition"
)

func (k Kind) IsValid() bool {
	switch k {
	case KindInstruction, KindMemory, KindPreference, KindSkill, KindAgent, KindProjectContext, KindToolDefinition:
		return true
	default:
		return false
	}
}

type Scope string

const (
	ScopeGlobal  Scope = "global"
	ScopeProject Scope = "project"
)

func (s Scope) IsValid() bool {
	return s == ScopeGlobal || s == ScopeProject
}

type Lifecycle string

const (
	LifecyclePersistent  Lifecycle = "persistent"
	LifecycleReplaceable Lifecycle = "replaceable"
	LifecycleTemporary   Lifecycle = "temporary"
	LifecycleHistorical  Lifecycle = "historical"
)

type Sensitivity string

const (
	SensitivityNormal  Sensitivity = "normal"
	SensitivityPrivate Sensitivity = "private"
	SensitivitySecret  Sensitivity = "secret"
)

type Provenance struct {
	Provider          string    `json:"provider"`
	MachineID         string    `json:"machine_id"`
	SourcePath        string    `json:"source_path"`
	ImportedAt        time.Time `json:"imported_at"`
	SourceFingerprint string    `json:"source_fingerprint"`
}

type Artifact struct {
	ID            string            `json:"id"`
	SchemaVersion string            `json:"schema_version"`
	Kind          Kind              `json:"kind"`
	Scope         Scope             `json:"scope"`
	Title         string            `json:"title"`
	Content       string            `json:"content"`
	Files         map[string]string `json:"files,omitempty"`
	ContentType   string            `json:"content_type"`
	Tags          []string          `json:"tags,omitempty"`
	Lifecycle     Lifecycle         `json:"lifecycle"`
	Sensitivity   Sensitivity       `json:"sensitivity"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Fingerprint   string            `json:"fingerprint"`
	Provenance    []Provenance      `json:"provenance"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

var (
	ErrInvalidArtifact         = errors.New("invalid artifact structure")
	ErrUnsupportedSchema       = errors.New("unsupported schema version")
	ErrSecretArtifactInStorage = errors.New("secret-classified artifact cannot enter canonical synchronized storage")
)

// Validate checks artifact invariant rules.
func (a *Artifact) Validate() error {
	if a.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("%w: got %s, want %s", ErrUnsupportedSchema, a.SchemaVersion, SchemaVersionV1)
	}

	if a.ID == "" {
		return fmt.Errorf("%w: missing ID", ErrInvalidArtifact)
	}

	if !a.Kind.IsValid() {
		return fmt.Errorf("%w: invalid kind %s", ErrInvalidArtifact, a.Kind)
	}

	if !a.Scope.IsValid() {
		return fmt.Errorf("%w: invalid scope %s", ErrInvalidArtifact, a.Scope)
	}

	if a.Sensitivity == SensitivitySecret {
		return ErrSecretArtifactInStorage
	}

	return nil
}

// UpdateFingerprint recomputes and updates the SHA-256 content fingerprint.
func (a *Artifact) UpdateFingerprint() string {
	a.Fingerprint = ComputeFingerprint(a.Kind, a.Scope, a.Title, a.Content, a.Files)
	return a.Fingerprint
}

// ComputeFingerprint computes deterministic SHA-256 fingerprint for normalized artifact content.
func ComputeFingerprint(kind Kind, scope Scope, title, content string, files map[string]string) string {
	normContent := NormalizeContent(content)

	var sb strings.Builder
	sb.WriteString(string(kind))
	sb.WriteString("|")
	sb.WriteString(string(scope))
	sb.WriteString("|")
	sb.WriteString(normContent)

	if len(files) > 0 {
		keys := make([]string, 0, len(files))
		for k := range files {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			sb.WriteString("|file:")
			sb.WriteString(k)
			sb.WriteString(":")
			sb.WriteString(NormalizeContent(files[k]))
		}
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}

// GenerateArtifactID generates a stable AgentPort artifact ID.
func GenerateArtifactID(kind Kind, fingerprint string) string {
	if len(fingerprint) > 16 {
		fingerprint = fingerprint[:16]
	}
	return fmt.Sprintf("apa_%s_%s", kind, fingerprint)
}

// Clone returns a deep copy of the Artifact.
func (a *Artifact) Clone() *Artifact {
	if a == nil {
		return nil
	}
	cp := *a

	if a.Files != nil {
		cp.Files = make(map[string]string, len(a.Files))
		for k, v := range a.Files {
			cp.Files[k] = v
		}
	}

	if a.Tags != nil {
		cp.Tags = make([]string, len(a.Tags))
		copy(cp.Tags, a.Tags)
	}

	if a.Provenance != nil {
		cp.Provenance = make([]Provenance, len(a.Provenance))
		copy(cp.Provenance, a.Provenance)
	}

	if a.Metadata != nil {
		cp.Metadata = make(map[string]string, len(a.Metadata))
		for k, v := range a.Metadata {
			cp.Metadata[k] = v
		}
	}

	return &cp
}
