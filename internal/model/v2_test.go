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
