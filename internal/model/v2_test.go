package model_test

import (
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/model"
)

func TestEnvelopeV2Validation(t *testing.T) {
	env := &model.EnvelopeV2{
		ID:            "apv2_1234567890abcdef",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		RevisionHash:  "abcdef123456",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		Memory: &model.MemoryPayload{
			Statement:  "User prefers Go.",
			Category:   model.CategoryPreference,
			Status:     model.MemoryStatusActive,
			Importance: 5,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}

	if err := env.Validate(); err != nil {
		t.Fatalf("expected envelope validation to pass, got: %v", err)
	}

	// Secret sensitivity check
	envSecret := *env
	envSecret.Sensitivity = model.SensitivitySecret
	if err := envSecret.Validate(); err == nil {
		t.Errorf("expected secret sensitivity envelope validation to fail")
	}
}

func TestMigrateV1ToV2(t *testing.T) {
	v1Art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindMemory,
		Scope:         model.ScopeGlobal,
		Title:         "V1 Memory",
		Content:       "User prefers dark mode",
		ContentType:   "text/plain",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	v1Art.UpdateFingerprint()
	v1Art.ID = model.GenerateArtifactID(v1Art.Kind, v1Art.Fingerprint)

	plan1, err := model.MigrateV1ToV2([]*model.Artifact{v1Art})
	if err != nil {
		t.Fatalf("MigrateV1ToV2 failed: %v", err)
	}

	if len(plan1.ConvertedV2) != 1 {
		t.Fatalf("expected 1 converted envelope, got %d", len(plan1.ConvertedV2))
	}

	env1 := plan1.ConvertedV2[0]
	if env1.SchemaVersion != model.SchemaVersionV2 {
		t.Errorf("expected schema version %s, got %s", model.SchemaVersionV2, env1.SchemaVersion)
	}
	if env1.Memory.Statement != v1Art.Content {
		t.Errorf("expected memory statement %s, got %s", v1Art.Content, env1.Memory.Statement)
	}

	// Test idempotence
	plan2, err := model.MigrateV1ToV2([]*model.Artifact{v1Art})
	if err != nil {
		t.Fatalf("second MigrateV1ToV2 failed: %v", err)
	}

	if plan1.ConvertedV2[0].ID != plan2.ConvertedV2[0].ID {
		t.Errorf("expected identical migrated V2 ID for idempotent run, got %s vs %s", plan1.ConvertedV2[0].ID, plan2.ConvertedV2[0].ID)
	}
}

func baseMemoryEnvelope() *model.EnvelopeV2 {
	return &model.EnvelopeV2{
		ID:            "apm_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Memory: &model.MemoryPayload{
			Statement:   "Base statement",
			Category:    model.CategoryPreference,
			Status:      model.MemoryStatusActive,
			Importance:  5,
			Confidence:  1.0,
			Derivation:  model.DerivationDirect,
			ReviewState: "approved",
		},
	}
}

func TestRevisionHashMemoryValidityChange(t *testing.T) {
	env1 := baseMemoryEnvelope()
	h1 := model.ComputeRevisionHash(env1)

	now := time.Now()
	env2 := env1.Clone()
	env2.Memory.ValidFrom = &now
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when ValidFrom changes")
	}

	later := now.Add(time.Hour)
	env3 := env2.Clone()
	env3.Memory.ValidUntil = &later
	h3 := model.ComputeRevisionHash(env3)

	if h2 == h3 {
		t.Errorf("expected RevisionHash to change when ValidUntil changes")
	}
}

func TestRevisionHashMemoryEvidenceChange(t *testing.T) {
	env1 := baseMemoryEnvelope()
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.Memory.Evidence = []model.EvidenceLink{
		{SourceRecordID: "sr1", SourceRevision: 1, ContentHash: "hash1", ExcerptHash: "ex1"},
	}
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when Evidence changes")
	}
}

func TestRevisionHashMemorySupersedesChange(t *testing.T) {
	env1 := baseMemoryEnvelope()
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.Memory.Supersedes = []string{"apm_old1"}
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when Supersedes changes")
	}
}

func TestRevisionHashMemoryConflictChange(t *testing.T) {
	env1 := baseMemoryEnvelope()
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.Memory.ConflictsWith = []string{"apm_conflict1"}
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when ConflictsWith changes")
	}
}

func TestRevisionHashSkillFileChange(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apsk_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindSkillPackage,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Skill: &model.SkillPackage{
			Name:        "test_skill",
			Description: "desc",
			SkillMD:     "content",
			Scripts:     map[string]string{"scripts/run.sh": "echo 1"},
			TrustState:  model.SkillTrustTrusted,
		},
	}
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.Skill.Scripts["scripts/run.sh"] = "echo 2"
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when Skill script content changes")
	}
}

func TestRevisionHashAgentCapabilityChange(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apag_test",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindAgentDef,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Agent: &model.AgentDef{
			Name:         "agent1",
			Description:  "desc",
			Instructions: "do stuff",
			Capabilities: []string{"cap1"},
		},
	}
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.Agent.Capabilities = []string{"cap1", "cap2"}
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when Agent capabilities change")
	}
}

func TestRevisionHashMCPArgumentOrderMatters(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apt_mcp",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMCPToolDef,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		MCPTool: &model.MCPToolDef{
			Name:      "test_mcp",
			Command:   "node",
			Args:      []string{"--input", "foo"},
			Transport: "stdio",
		},
	}
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.MCPTool.Args = []string{"foo", "--input"}
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to be DIFFERENT when MCP argument order changes")
	}
}

func TestRevisionHashMCPWorkingDirPolicyChange(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apt_mcp",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMCPToolDef,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		MCPTool: &model.MCPToolDef{
			Name:             "test_mcp",
			Command:          "node",
			Transport:        "stdio",
			WorkingDirPolicy: "root",
		},
	}
	h1 := model.ComputeRevisionHash(env1)

	env2 := env1.Clone()
	env2.MCPTool.WorkingDirPolicy = "workspace"
	h2 := model.ComputeRevisionHash(env2)

	if h1 == h2 {
		t.Errorf("expected RevisionHash to change when WorkingDirPolicy changes")
	}
}

func TestRevisionHashMCPEnvOrderingDeterministic(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apt_mcp",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMCPToolDef,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		MCPTool: &model.MCPToolDef{
			Name:        "test_mcp",
			Command:     "node",
			Transport:   "stdio",
			EnvVarNames: []string{"VAR_B", "VAR_A"},
		},
	}

	env2 := env1.Clone()
	env2.MCPTool.EnvVarNames = []string{"VAR_A", "VAR_B"}

	if model.ComputeRevisionHash(env1) != model.ComputeRevisionHash(env2) {
		t.Errorf("expected RevisionHash to be identical for unordered EnvVarNames permutations")
	}
}

func TestRevisionHashMapOrderingDeterministic(t *testing.T) {
	env1 := &model.EnvelopeV2{
		ID:            "apm_meta",
		SchemaVersion: model.SchemaVersionV2,
		Kind:          model.KindMemoryV2,
		Scope:         model.ScopeGlobal,
		Revision:      1,
		Metadata: map[string]string{
			"key_a": "val_a",
			"key_b": "val_b",
		},
		Memory: &model.MemoryPayload{
			Statement:  "stmt",
			Category:   model.CategoryPreference,
			Status:     model.MemoryStatusActive,
			Importance: 5,
			Confidence: 1.0,
			Derivation: model.DerivationDirect,
		},
	}

	env2 := env1.Clone()
	env2.Metadata = map[string]string{
		"key_b": "val_b",
		"key_a": "val_a",
	}

	if model.ComputeRevisionHash(env1) != model.ComputeRevisionHash(env2) {
		t.Errorf("expected RevisionHash to be identical regardless of Metadata map iteration order")
	}
}
