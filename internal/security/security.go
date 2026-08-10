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
	regexp.MustCompile(`(?i)AGE-SECRET-KEY-1[a-z0-9]{50,}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{60,}`),
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

// ValidateEnvelopeSecurity performs comprehensive security check on a Schema V2 Envelope.
func ValidateEnvelopeSecurity(env *model.EnvelopeV2) error {
	if env.Sensitivity == model.SensitivitySecret {
		return ErrSecretDetected
	}

	if env.SourceRecord != nil {
		hasSecret, reason := ScanContentForSecrets(env.SourceRecord.Content)
		if hasSecret {
			return fmt.Errorf("%w: source record content (%s)", ErrSecretDetected, reason)
		}
		for fName, fContent := range env.SourceRecord.Files {
			if res := InspectFileName(fName); res.Decision == DecisionReject {
				return fmt.Errorf("%w: file %s (%s)", ErrDisallowedFile, fName, res.Reason)
			}
			if hasSubSecret, subReason := ScanContentForSecrets(fContent); hasSubSecret {
				return fmt.Errorf("%w: file %s (%s)", ErrSecretDetected, fName, subReason)
			}
		}
	}

	if env.Memory != nil {
		if hasSecret, reason := ScanContentForSecrets(env.Memory.Statement); hasSecret {
			return fmt.Errorf("%w: memory statement (%s)", ErrSecretDetected, reason)
		}
	}

	if env.Skill != nil {
		if res := InspectFileName("SKILL.md"); res.Decision == DecisionReject {
			return fmt.Errorf("%w: skill md (%s)", ErrDisallowedFile, res.Reason)
		}
		if hasSecret, reason := ScanContentForSecrets(env.Skill.SkillMD); hasSecret {
			return fmt.Errorf("%w: skill md (%s)", ErrSecretDetected, reason)
		}
		for sName, sContent := range env.Skill.Scripts {
			if res := InspectFileName(sName); res.Decision == DecisionReject {
				return fmt.Errorf("%w: script %s (%s)", ErrDisallowedFile, sName, res.Reason)
			}
			if hasSecret, reason := ScanContentForSecrets(sContent); hasSecret {
				return fmt.Errorf("%w: script %s (%s)", ErrSecretDetected, sName, reason)
			}
		}
		for rName, rContent := range env.Skill.References {
			if res := InspectFileName(rName); res.Decision == DecisionReject {
				return fmt.Errorf("%w: reference %s (%s)", ErrDisallowedFile, rName, res.Reason)
			}
			if hasSecret, reason := ScanContentForSecrets(rContent); hasSecret {
				return fmt.Errorf("%w: reference %s (%s)", ErrSecretDetected, rName, reason)
			}
		}
		for aName, aContent := range env.Skill.Assets {
			if res := InspectFileName(aName); res.Decision == DecisionReject {
				return fmt.Errorf("%w: asset %s (%s)", ErrDisallowedFile, aName, res.Reason)
			}
			if hasSecret, reason := ScanContentForSecrets(aContent); hasSecret {
				return fmt.Errorf("%w: asset %s (%s)", ErrSecretDetected, aName, reason)
			}
		}
	}

	return nil
}
