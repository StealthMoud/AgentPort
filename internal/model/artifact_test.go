package model_test

import (
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/model"
)

func TestArtifactValidationAndFingerprint(t *testing.T) {
	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Code Style Preference",
		Content:       "Always use Go 1.26 features.\r\nTrailing space   \n\n\n\nEnd line",
		ContentType:   "text/markdown",
		Lifecycle:     model.LifecyclePersistent,
		Sensitivity:   model.SensitivityNormal,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	fp := art.UpdateFingerprint()
	if fp == "" {
		t.Fatalf("expected non-empty fingerprint")
	}

	art.ID = model.GenerateArtifactID(art.Kind, fp)

	if err := art.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Secret validation error test
	artSecret := *art
	artSecret.Sensitivity = model.SensitivitySecret
	if err := artSecret.Validate(); err == nil {
		t.Fatalf("expected secret artifact validation error, got nil")
	}
}

func TestNormalizeContent(t *testing.T) {
	input := "Line 1  \r\nLine 2 \r\n\r\n\r\nLine 3   "
	expected := "Line 1\nLine 2\n\nLine 3"

	got := model.NormalizeContent(input)
	if got != expected {
		t.Errorf("NormalizeContent failed.\nExpected: %q\nGot:      %q", expected, got)
	}
}
