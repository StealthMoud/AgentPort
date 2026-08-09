package security

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/StealthMoud/AgentPort/internal/model"
)

var (
	ErrSecretDetected = errors.New("potential secret detected in artifact content")
	ErrDisallowedFile = errors.New("file rejected by security policy")
	ErrDisallowedPath = errors.New("path rejected by security policy")
)

type ScanDecision string

const (
	DecisionAllow  ScanDecision = "allow"
	DecisionIgnore ScanDecision = "ignore"
	DecisionReject ScanDecision = "reject"
)

type SecurityCheckResult struct {
	Decision ScanDecision
	Reason   string
}

// Regex patterns for detecting secrets in content.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----`),
	regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{58}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{82}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}`),
	regexp.MustCompile(`(?i)bearer\s+ey[a-zA-Z0-9_-]{15,}\.ey[a-zA-Z0-9_-]{15,}`),
}

// High risk file names / extensions / keywords.
var forbiddenFileKeywords = []string{
	".env",
	"credentials",
	"auth",
	"tokens",
	"cookies",
	"sessions",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
	".pem",
	".pkcs12",
	".pfx",
	".keystore",
	"oauth",
}

// InspectFileName checks if a file name or path is allowed, ignored, or rejected.
func InspectFileName(path string) SecurityCheckResult {
	base := strings.ToLower(filepath.Base(path))

	for _, kw := range forbiddenFileKeywords {
		if strings.Contains(base, kw) {
			return SecurityCheckResult{
				Decision: DecisionReject,
				Reason:   fmt.Sprintf("file matches secret rule: %s", kw),
			}
		}
	}

	// Ignore common cache / session / log / lock files
	if strings.HasSuffix(base, ".log") || strings.HasSuffix(base, ".tmp") || strings.HasSuffix(base, ".cache") || base == ".ds_store" {
		return SecurityCheckResult{
			Decision: DecisionIgnore,
			Reason:   "temporary or cache file ignored",
		}
	}

	return SecurityCheckResult{
		Decision: DecisionAllow,
		Reason:   "filename passed security checks",
	}
}

// ScanContentForSecrets inspects textual content for high-risk secret patterns.
func ScanContentForSecrets(content string) (bool, string) {
	for _, pattern := range secretPatterns {
		if pattern.MatchString(content) {
			return true, fmt.Sprintf("content matched secret pattern: %s", pattern.String())
		}
	}
	return false, ""
}

// ValidateArtifactSecurity performs comprehensive security check on an artifact.
func ValidateArtifactSecurity(art *model.Artifact) error {
	if art.Sensitivity == model.SensitivitySecret {
		return ErrSecretDetected
	}

	hasSecret, reason := ScanContentForSecrets(art.Content)
	if hasSecret {
		return fmt.Errorf("%w: %s", ErrSecretDetected, reason)
	}

	for fileName, fileContent := range art.Files {
		res := InspectFileName(fileName)
		if res.Decision == DecisionReject {
			return fmt.Errorf("%w: file %s (%s)", ErrDisallowedFile, fileName, res.Reason)
		}

		hasSubSecret, subReason := ScanContentForSecrets(fileContent)
		if hasSubSecret {
			return fmt.Errorf("%w: file %s (%s)", ErrSecretDetected, fileName, subReason)
		}
	}

	return nil
}
