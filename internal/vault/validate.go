package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
)

type ValidationResult struct {
	TotalArtifacts int      `json:"total_artifacts"`
	ValidArtifacts int      `json:"valid_artifacts"`
	Healthy        bool     `json:"healthy"`
	Errors         []string `json:"errors"`
	Warnings       []string `json:"warnings"`
}

// Validate performs a comprehensive integrity check on local vault state.
func (v *Vault) Validate() *ValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	res := &ValidationResult{
		Healthy:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	if v.Metadata == nil {
		res.Healthy = false
		res.Errors = append(res.Errors, "missing vault metadata")
		return res
	}

	if v.Key == nil || v.Key.Identity == nil {
		res.Healthy = false
		res.Errors = append(res.Errors, "missing encryption key identity")
	}

	artifacts := v.ListArtifacts()
	res.TotalArtifacts = len(artifacts)

	for _, art := range artifacts {
		if err := art.Validate(); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("artifact %s: %v", art.ID, err))
			continue
		}

		if err := security.ValidateArtifactSecurity(art); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("artifact %s security failure: %v", art.ID, err))
			continue
		}

		expectedFp := model.ComputeFingerprint(art.Kind, art.Scope, art.Title, art.Content, art.Files)
		if art.Fingerprint != expectedFp {
			res.Errors = append(res.Errors, fmt.Sprintf("artifact %s fingerprint mismatch: got %s, expected %s", art.ID, art.Fingerprint, expectedFp))
			continue
		}

		res.ValidArtifacts++
	}

	// Plaintext leak check in sync repo
	syncObjectsDir := filepath.Join(v.cfg.SyncRepoDir, "objects")
	if _, err := os.Stat(syncObjectsDir); err == nil {
		_ = filepath.Walk(syncObjectsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Objects in sync repo must end with .age or be manifest/vault json files
			ext := filepath.Ext(path)
			if ext != ".age" && filepath.Base(path) != "vault.json" && filepath.Base(path) != "manifest.json" {
				res.Errors = append(res.Errors, fmt.Sprintf("unencrypted file found in sync repository: %s", path))
			}

			// Content inspection for plaintext keywords
			if ext != ".age" {
				data, err := os.ReadFile(path)
				if err == nil {
					hasSecret, reason := security.ScanContentForSecrets(string(data))
					if hasSecret {
						res.Errors = append(res.Errors, fmt.Sprintf("secret detected in sync repo file %s: %s", path, reason))
					}
					if strings.Contains(string(data), "AGE-SECRET-KEY-1") {
						res.Errors = append(res.Errors, fmt.Sprintf("private encryption key leaked in sync repo file: %s", path))
					}
				}
			}
			return nil
		})
	}

	if len(res.Errors) > 0 {
		res.Healthy = false
	}

	return res
}
