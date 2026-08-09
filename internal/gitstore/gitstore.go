package gitstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

var (
	ErrSyncConflict = errors.New("git remote and local branch have diverged - automatic overwrite refused")
	ErrGitExec      = errors.New("git execution error")
)

type ManifestObject struct {
	OpaqueID      string    `json:"opaque_id"`
	Fingerprint   string    `json:"fingerprint"`
	EncryptedSize int64     `json:"encrypted_size"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Manifest struct {
	SchemaVersion string                     `json:"schema_version"`
	VaultID       string                     `json:"vault_id"`
	UpdatedAt     time.Time                  `json:"updated_at"`
	Objects       map[string]*ManifestObject `json:"objects"` // Keyed by artifact ID
}

type SyncResult struct {
	LocalAhead            bool     `json:"local_ahead"`
	RemoteAhead           bool     `json:"remote_ahead"`
	ObjectsEncryptedCount int      `json:"objects_encrypted_count"`
	ObjectsDecryptedCount int      `json:"objects_decrypted_count"`
	CommitSHA             string   `json:"commit_sha,omitempty"`
	Message               string   `json:"message"`
	DryRun                bool     `json:"dry_run"`
	Warnings              []string `json:"warnings,omitempty"`
}

type Store struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Store {
	return &Store{cfg: cfg}
}

func (s *Store) execGit(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = s.cfg.SyncRepoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w (git %s): %s", ErrGitExec, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// EnsureRepo initializes a git repository in SyncRepoDir if not existing.
func (s *Store) EnsureRepo(ctx context.Context) error {
	if err := os.MkdirAll(s.cfg.SyncRepoDir, 0700); err != nil {
		return err
	}

	gitDir := filepath.Join(s.cfg.SyncRepoDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		if _, err := s.execGit(ctx, "init"); err != nil {
			return err
		}
		_, _ = s.execGit(ctx, "config", "user.name", "AgentPort")
		_, _ = s.execGit(ctx, "config", "user.email", "agentport@local.internal")
	}

	return nil
}

// SetRemote sets the git remote "origin".
func (s *Store) SetRemote(ctx context.Context, url string) error {
	if err := s.EnsureRepo(ctx); err != nil {
		return err
	}

	_, err := s.execGit(ctx, "remote", "set-url", "origin", url)
	if err != nil {
		_, err = s.execGit(ctx, "remote", "add", "origin", url)
	}
	return err
}

// GetRemote returns the configured "origin" remote URL.
func (s *Store) GetRemote(ctx context.Context) (string, error) {
	if err := s.EnsureRepo(ctx); err != nil {
		return "", err
	}
	return s.execGit(ctx, "remote", "get-url", "origin")
}

// Sync performs encrypted vault synchronization.
func (s *Store) Sync(ctx context.Context, v *vault.Vault, dryRun bool) (*SyncResult, error) {
	if err := s.EnsureRepo(ctx); err != nil {
		return nil, err
	}

	// 1. Integrity check on local vault before sync
	validation := v.Validate()
	if !validation.Healthy {
		return nil, fmt.Errorf("refusing sync: local vault is unhealthy: %v", validation.Errors)
	}

	res := &SyncResult{DryRun: dryRun}

	// 2. Check remote and fetch incoming state FIRST
	remoteURL, _ := s.GetRemote(ctx)
	if remoteURL != "" {
		if _, fetchErr := s.execGit(ctx, "fetch", "origin"); fetchErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("fetch origin failed: %v", fetchErr))
		} else {
			localRev, _ := s.execGit(ctx, "rev-parse", "HEAD")
			remoteRev, _ := s.execGit(ctx, "rev-parse", "origin/main")

			if remoteRev != "" {
				if localRev == "" {
					res.RemoteAhead = true
				} else if localRev != remoteRev {
					baseRev, _ := s.execGit(ctx, "merge-base", "HEAD", "origin/main")
					if baseRev == localRev {
						res.RemoteAhead = true
					} else if baseRev == remoteRev {
						res.LocalAhead = true
					} else {
						return nil, ErrSyncConflict
					}
				}
			}
		}
	}

	// 3. If remote is ahead, pull incoming encrypted objects first
	if res.RemoteAhead && !dryRun {
		localRev, _ := s.execGit(ctx, "rev-parse", "HEAD")
		if localRev == "" {
			_, err := s.execGit(ctx, "checkout", "-B", "main", "origin/main")
			if err != nil {
				return nil, fmt.Errorf("failed checkout remote branch: %w", err)
			}
		} else {
			_, err := s.execGit(ctx, "pull", "--ff-only", "origin", "main")
			if err != nil {
				return nil, fmt.Errorf("failed fast-forward pull: %w", err)
			}
		}

		decryptedCount, err := s.decryptObjectsIntoVault(v)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting incoming remote objects: %w", err)
		}
		res.ObjectsDecryptedCount = decryptedCount
	}

	// 4. Load manifest from sync repo
	manifestPath := filepath.Join(s.cfg.SyncRepoDir, "manifest.json")
	manifest := &Manifest{
		SchemaVersion: model.SchemaVersionV1,
		VaultID:       v.Metadata.VaultID,
		UpdatedAt:     time.Now(),
		Objects:       make(map[string]*ManifestObject),
	}

	if data, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(data, manifest)
	}

	objectsDir := filepath.Join(s.cfg.SyncRepoDir, "objects")
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		return nil, err
	}

	// Save vault metadata to sync repo
	vaultMetaBytes, err := json.MarshalIndent(v.Metadata, "", "  ")
	if err == nil {
		_ = fsutil.WriteFileAtomic(filepath.Join(s.cfg.SyncRepoDir, "vault.json"), vaultMetaBytes, 0600)
	}

	// 5. Encrypt changed local artifacts
	artifacts := v.ListArtifacts()
	changedCount := 0

	for _, art := range artifacts {
		if err := security.ValidateArtifactSecurity(art); err != nil {
			return nil, fmt.Errorf("security check failed during sync for artifact %s: %w", art.ID, err)
		}

		existingObj, exists := manifest.Objects[art.ID]
		if !exists || existingObj.Fingerprint != art.Fingerprint {
			artBytes, err := json.MarshalIndent(art, "", "  ")
			if err != nil {
				return nil, err
			}

			ciphertext, err := crypt.Encrypt(v.Key.Recipient, artBytes)
			if err != nil {
				return nil, fmt.Errorf("failed encrypting artifact %s: %w", art.ID, err)
			}

			opaqueID := model.ComputeFingerprint(art.Kind, art.Scope, art.ID, art.Fingerprint, nil)[:24]
			objectFileName := opaqueID + ".age"
			objectPath := filepath.Join(objectsDir, objectFileName)

			if !dryRun {
				if err := fsutil.WriteFileAtomic(objectPath, ciphertext, 0600); err != nil {
					return nil, err
				}
				manifest.Objects[art.ID] = &ManifestObject{
					OpaqueID:      opaqueID,
					Fingerprint:   art.Fingerprint,
					EncryptedSize: int64(len(ciphertext)),
					UpdatedAt:     time.Now(),
				}
			}
			changedCount++
		}
	}

	res.ObjectsEncryptedCount = changedCount

	if dryRun {
		res.Message = "Sync dry-run completed successfully"
		return res, nil
	}

	// Save updated manifest
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(manifestPath, manifestBytes, 0600); err != nil {
		return nil, err
	}

	// 6. Commit local changes if anything changed or local is uncommitted
	status, _ := s.execGit(ctx, "status", "--porcelain")
	if strings.TrimSpace(status) != "" {
		_, _ = s.execGit(ctx, "add", "-A")
		sha, commitErr := s.execGit(ctx, "commit", "-m", "sync: update AgentPort vault")
		if commitErr == nil {
			res.CommitSHA = sha
		}
	}

	// 7. Push to remote if remote exists and local has commits to push
	if remoteURL != "" {
		_, pushErr := s.execGit(ctx, "push", "origin", "HEAD:main")
		if pushErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("git push failed: %v", pushErr))
		}
	}

	res.Message = "Sync completed successfully"
	return res, nil
}

func (s *Store) decryptObjectsIntoVault(v *vault.Vault) (int, error) {
	manifestPath := filepath.Join(s.cfg.SyncRepoDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return 0, nil
	}

	manifest := &Manifest{}
	if err := json.Unmarshal(data, manifest); err != nil {
		return 0, err
	}

	objectsDir := filepath.Join(s.cfg.SyncRepoDir, "objects")
	decryptedCount := 0

	keys := make([]string, 0, len(manifest.Objects))
	for k := range manifest.Objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, artID := range keys {
		obj := manifest.Objects[artID]
		objFile := filepath.Join(objectsDir, obj.OpaqueID+".age")
		ciphertext, err := os.ReadFile(objFile)
		if err != nil {
			continue
		}

		plaintext, err := crypt.Decrypt(v.Key.Identity, ciphertext)
		if err != nil {
			return decryptedCount, fmt.Errorf("failed decrypting object %s: %w", obj.OpaqueID, err)
		}

		art := &model.Artifact{}
		if err := json.Unmarshal(plaintext, art); err != nil {
			return decryptedCount, fmt.Errorf("failed parsing decrypted artifact: %w", err)
		}

		if err := v.SaveArtifact(art); err != nil {
			return decryptedCount, fmt.Errorf("failed saving decrypted artifact to vault: %w", err)
		}
		decryptedCount++
	}

	return decryptedCount, nil
}
