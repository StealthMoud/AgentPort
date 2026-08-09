package security_test

import (
	"testing"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
)

func TestInspectFileName(t *testing.T) {
	tests := []struct {
		path     string
		expected security.ScanDecision
	}{
		{".env", security.DecisionReject},
		{"/home/user/.aws/credentials", security.DecisionReject},
		{"id_rsa", security.DecisionReject},
		{"app.log", security.DecisionIgnore},
		{"CLAUDE.md", security.DecisionAllow},
		{"AGENTS.md", security.DecisionAllow},
	}

	for _, tt := range tests {
		res := security.InspectFileName(tt.path)
		if res.Decision != tt.expected {
			t.Errorf("for path %s expected %s, got %s (reason: %s)", tt.path, tt.expected, res.Decision, res.Reason)
		}
	}
}

func TestScanContentForSecrets(t *testing.T) {
	secretContent := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	hasSecret, _ := security.ScanContentForSecrets(secretContent)
	if !hasSecret {
		t.Errorf("expected secret detection for RSA key")
	}

	safeContent := "Use environment variable ${GITHUB_TOKEN} for CI authentication."
	hasSecretSafe, _ := security.ScanContentForSecrets(safeContent)
	if hasSecretSafe {
		t.Errorf("expected safe environment variable reference to pass secret scanner")
	}
}

func TestValidateArtifactSecurity(t *testing.T) {
	art := &model.Artifact{
		SchemaVersion: model.SchemaVersionV1,
		Kind:          model.KindInstruction,
		Scope:         model.ScopeGlobal,
		Title:         "Safe Instruction",
		Content:       "Always format code with gofmt.",
		Sensitivity:   model.SensitivityNormal,
	}

	if err := security.ValidateArtifactSecurity(art); err != nil {
		t.Fatalf("expected valid artifact, got error: %v", err)
	}

	artSecret := *art
	artSecret.Content = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	if err := security.ValidateArtifactSecurity(&artSecret); err == nil {
		t.Fatalf("expected secret detection error for GitHub token")
	}
}
