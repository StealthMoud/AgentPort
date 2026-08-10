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

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/revision"
	"github.com/StealthMoud/AgentPort/internal/security"
	"github.com/StealthMoud/AgentPort/internal/syncv2"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

var (
	ErrSyncConflict           = errors.New("git remote and local branch have diverged - automatic overwrite refused")
	ErrGitExec                = errors.New("git execution error")
	ErrRemoteChangedRepeatedly = errors.New("remote changed repeatedly during sync push - max retries exceeded")
)

type ManifestObject struct {
	OpaqueID             string    `json:"opaque_id"`
	Fingerprint          string    `json:"fingerprint"`
	EncryptedSize        int64     `json:"encrypted_size"`
	UpdatedAt            time.Time `json:"updated_at"`
	IsTombstone          bool      `json:"is_tombstone,omitempty"`
	DeletedRevision      int       `json:"deleted_revision,omitempty"`
	OriginMachineID      string    `json:"origin_machine_id,omitempty"`
	PreviousRevisionHash string    `json:"previous_revision_hash,omitempty"`
}

type Manifest struct {
	SchemaVersion string                     `json:"schema_version"`
	VaultID       string                     `json:"vault_id"`
	UpdatedAt     time.Time                  `json:"updated_at"`
	Objects       map[string]*ManifestObject `json:"objects"` // Keyed by artifact ID
}

const (
	SyncStatusSuccess           = "success"
	SyncStatusPartial           = "partial"
	SyncStatusConflict          = "conflict"
	SyncStatusRemoteUnavailable = "remote_unavailable"
	SyncStatusPushFailed        = "push_failed"
	SyncStatusValidationFailed  = "validation_failed"
)

type SyncResult struct {
	Status                string   `json:"status"`
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
		if _, err := s.execGit(ctx, "init", "-b", "main"); err != nil {
			if _, err := s.execGit(ctx, "init"); err != nil {
				return err
			}
			_, _ = s.execGit(ctx, "checkout", "-B", "main")
		}
		_, _ = s.execGit(ctx, "config", "user.name", "AgentPort")
		_, _ = s.execGit(ctx, "config", "user.email", "agentport@local.internal")
	} else {
		// Ensure current branch is main
		_, _ = s.execGit(ctx, "checkout", "-B", "main")
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

// GetRemote returns the configured "origin" remote URL without initializing a repo if missing.
func (s *Store) GetRemote(ctx context.Context) (string, error) {
	gitDir := filepath.Join(s.cfg.SyncRepoDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return "", nil
	}
	return s.execGit(ctx, "remote", "get-url", "origin")
}

// Sync performs encrypted vault synchronization. If Sync Protocol V2 is active, it runs V2 protocol logic.
func (s *Store) Sync(ctx context.Context, v *vault.Vault, dryRun bool) (*SyncResult, error) {
	// Check if Protocol V2 is active
	protoPath := filepath.Join(s.cfg.SyncRepoDir, syncv2.ProtocolFileName)
	if _, err := os.Stat(protoPath); err == nil {
		return s.SyncV2(ctx, v, dryRun)
	}

	// Legacy V1 Sync Path
	return s.syncV1(ctx, v, dryRun)
}

// SyncV2 executes Phase 6 Sync Protocol V2 multi-device synchronization.
func (s *Store) SyncV2(ctx context.Context, v *vault.Vault, dryRun bool) (*SyncResult, error) {
	if dryRun {
		return &SyncResult{
			Status: SyncStatusSuccess,
			DryRun: true,
		}, nil
	}

	if err := s.EnsureRepo(ctx); err != nil {
		return nil, err
	}

	// 1. Verify local vault health
	if v != nil {
		validation := v.Validate()
		if !validation.Healthy {
			return nil, fmt.Errorf("refusing sync: local vault is unhealthy: %v", validation.Errors)
		}
	}

	// 2. Load device keys & trust anchor
	devKeys, err := device.LoadDeviceKeys(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("device keys required for sync protocol v2: %w", err)
	}

	trustAnchor, err := device.LoadTrustAnchor(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed loading local trust anchor: %w", err)
	}

	res := &SyncResult{DryRun: dryRun}
	remoteURL, _ := s.GetRemote(ctx)

	// 3. Fetch remote if configured
	if remoteURL != "" {
		if _, fetchErr := s.execGit(ctx, "fetch", "origin"); fetchErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("fetch origin failed: %v", fetchErr))
		}
	}

	// 4. Load & validate latest RegistryEpoch
	activeRegistry, err := s.loadLatestRegistry(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed loading device registry: %w", err)
	}

	if err := device.VerifyAgainstTrustAnchor(trustAnchor, activeRegistry); err != nil {
		return nil, err
	}

	if !activeRegistry.IsDeviceActive(devKeys.DeviceID) {
		return nil, device.ErrDeviceNotAuthorized
	}

	// 5. Load local & remote catalogs
	localCat, _ := s.loadCurrentCatalog(ctx, devKeys.AgeIdentity)
	remoteCat, _ := s.loadRemoteCatalog(ctx, devKeys.AgeIdentity)

	// 6. Build local catalog if not existing locally
	if localCat == nil && v != nil {
		localCat, err = s.buildCatalogFromVault(v, devKeys, activeRegistry)
		if err != nil {
			return nil, fmt.Errorf("failed building catalog from local vault: %w", err)
		}
	}

	// 7. Perform Application-Level 3-way/ancestral Merge
	mergeRes, err := syncv2.MergeCatalogs(localCat, remoteCat, activeRegistry, devKeys)
	if err != nil {
		return nil, fmt.Errorf("application merge failed: %w", err)
	}

	if mergeRes.HasConflicts {
		res.Status = SyncStatusConflict
		res.Message = fmt.Sprintf("Sync detected %d unresolved application conflicts", len(mergeRes.NewConflicts))
	} else {
		res.Status = SyncStatusSuccess
		res.Message = "Sync completed successfully"
	}

	// 8. Encrypt & write merged catalog & objects
	mergedCat := mergeRes.MergedCatalog

	recipients := make([]age.Recipient, 0, len(activeRegistry.ActiveDevices)+1)
	for _, devRec := range activeRegistry.ActiveDevices {
		if devRec.Status == device.StatusActive {
			if r, err := device.GetRecipientFromRecipientString(devRec.AgeRecipient); err == nil {
				recipients = append(recipients, r)
			}
		}
	}
	// Add recovery recipient if configured
	if recRecipientStr, _, _, err := device.LoadRecoveryPublicConfig(s.cfg); err == nil && recRecipientStr != "" {
		if r, err := device.GetRecipientFromRecipientString(recRecipientStr); err == nil {
			recipients = append(recipients, r)
		}
	}

	catBytes, err := syncv2.EncryptCatalog(mergedCat, recipients)
	if err != nil {
		return nil, fmt.Errorf("failed encrypting merged catalog: %w", err)
	}

	catFileName := mergedCat.CatalogID + ".age"
	catPath := filepath.Join(s.cfg.SyncRepoDir, syncv2.CatalogsDir, catFileName)
	if err := fsutil.WriteFileAtomic(catPath, catBytes, 0600); err != nil {
		return nil, err
	}

	catHeadData := map[string]string{
		"catalog_id": mergedCat.CatalogID,
		"file":       filepath.Join(syncv2.CatalogsDir, catFileName),
	}
	catHeadBytes, _ := json.MarshalIndent(catHeadData, "", "  ")
	_ = fsutil.WriteFileAtomic(filepath.Join(s.cfg.SyncRepoDir, syncv2.CatalogHeadFile), catHeadBytes, 0600)

	// Save protocol metadata
	protoMeta := &syncv2.ProtocolMetadata{
		ProtocolVersion:  "2.0",
		VaultID:          activeRegistry.VaultID,
		RegistryEpoch:    activeRegistry.Epoch,
		CatalogHeadID:    mergedCat.CatalogID,
	}
	_ = syncv2.WriteProtocolMetadata(s.cfg.SyncRepoDir, protoMeta)

	// 9. Stage & Commit
	if _, err := s.execGit(ctx, "add", "-A"); err != nil {
		return nil, fmt.Errorf("failed git add: %w", err)
	}

	hasStaged, err := s.hasAnyStagedChanges(ctx)
	if err != nil {
		return nil, err
	}

	if hasStaged {
		commitMsg := fmt.Sprintf("sync: protocol v2 state updated (%s)", time.Now().Format(time.RFC3339))
		sha, err := s.execGit(ctx, "commit", "-m", commitMsg)
		if err != nil {
			return nil, fmt.Errorf("failed git commit: %w", err)
		}
		res.CommitSHA = sha

		// 10. Push with bounded retry loop if remote diverged
		if remoteURL != "" {
			maxRetries := 5
			pushSuccess := false
			for i := 0; i < maxRetries; i++ {
				_, pushErr := s.execGit(ctx, "push", "origin", "main")
				if pushErr == nil {
					pushSuccess = true
					break
				}
				// Retry push: fetch, pull/rebase checkout, rerun merge
				_, _ = s.execGit(ctx, "fetch", "origin")
				_, _ = s.execGit(ctx, "rebase", "origin/main")
			}
			if !pushSuccess {
				res.Status = SyncStatusPushFailed
				res.Message = "push failed after retries: " + ErrRemoteChangedRepeatedly.Error()
				return res, nil
			}
		}
	}

	// 11. Decrypt merged objects into local vault
	if v != nil {
		decryptedCount, err := s.decryptCatalogIntoVault(v, mergedCat, devKeys.AgeIdentity)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("failed applying merged objects into vault: %v", err))
		}
		res.ObjectsDecryptedCount = decryptedCount
	}

	// 12. Update local trust anchor
	trustAnchor.HighestRegistryEpoch = activeRegistry.Epoch
	trustAnchor.LastAcceptedCatalogID = mergedCat.CatalogID
	_ = device.SaveTrustAnchor(s.cfg, trustAnchor)

	return res, nil
}

func (s *Store) loadLatestRegistry(ctx context.Context) (*device.RegistryEpoch, error) {
	regHeadPath := filepath.Join(s.cfg.SyncRepoDir, syncv2.RegistryHeadFile)
	bytes, err := os.ReadFile(regHeadPath)
	if err != nil {
		return nil, fmt.Errorf("missing registry-head.json: %w", err)
	}
	epoch := &device.RegistryEpoch{}
	if err := json.Unmarshal(bytes, epoch); err != nil {
		return nil, fmt.Errorf("corrupt registry-head.json: %w", err)
	}
	return epoch, nil
}

func (s *Store) loadCurrentCatalog(ctx context.Context, identity age.Identity) (*syncv2.Catalog, error) {
	catHeadPath := filepath.Join(s.cfg.SyncRepoDir, syncv2.CatalogHeadFile)
	data, err := os.ReadFile(catHeadPath)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	catFile := filepath.Join(s.cfg.SyncRepoDir, m["file"])
	ciphertext, err := os.ReadFile(catFile)
	if err != nil {
		return nil, err
	}

	return syncv2.DecryptCatalog(ciphertext, identity)
}

func (s *Store) loadRemoteCatalog(ctx context.Context, identity age.Identity) (*syncv2.Catalog, error) {
	remoteRev, err := s.execGit(ctx, "rev-parse", "origin/main")
	if err != nil || remoteRev == "" {
		return nil, nil
	}

	// Read remote catalog-head.json from origin/main
	catHeadBytes, err := s.execGit(ctx, "show", "origin/main:"+syncv2.CatalogHeadFile)
	if err != nil || catHeadBytes == "" {
		return nil, nil
	}
	m := make(map[string]string)
	if err := json.Unmarshal([]byte(catHeadBytes), &m); err != nil {
		return nil, nil
	}

	relPath := m["file"]
	ciphertextStr, err := s.execGit(ctx, "show", "origin/main:"+relPath)
	if err != nil || ciphertextStr == "" {
		return nil, nil
	}

	return syncv2.DecryptCatalog([]byte(ciphertextStr), identity)
}

func (s *Store) buildCatalogFromVault(v *vault.Vault, devKeys *device.DeviceKeys, activeRegistry *device.RegistryEpoch) (*syncv2.Catalog, error) {
	entities := v.ListEntities()
	revisionGraph := make(map[string]*revision.RevisionRecord)
	entityHeads := make(map[string]string)
	objectRefs := make(map[string]*syncv2.ObjectRefInfo)

	revStoreDir := filepath.Join(s.cfg.VaultDir, "revisions")
	revStore, _ := revision.NewStore(revStoreDir)

	for _, env := range entities {
		headRev, ok := revStore.GetEntityHeadRevision(env.ID)
		if !ok {
			headRev = &revision.RevisionRecord{
				RevisionID:           revision.GenerateRevisionID(),
				EntityID:             env.ID,
				RevisionNumber:       env.Revision,
				SemanticRevisionHash: env.RevisionHash,
				AuthorDeviceID:       devKeys.DeviceID,
				CreatedAt:            env.CreatedAt,
			}
			_ = revStore.SaveRevision(headRev)
		}
		revisionGraph[headRev.RevisionID] = headRev
		entityHeads[env.ID] = headRev.RevisionID
	}

	regHash, _ := device.ComputeRegistryHash(activeRegistry)
	cat := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          activeRegistry.VaultID,
		CatalogID:        syncv2.GenerateCatalogID(),
		RegistryEpoch:    activeRegistry.Epoch,
		RegistryHash:     regHash,
		RecipientSetHash: crypt.RecipientSetHash(activeRegistry.ActiveRecipients()),
		CreatedAt:        time.Now().UTC(),
		WriterDeviceID:   devKeys.DeviceID,
		StateRoot:        syncv2.ComputeStateRoot(entityHeads, revisionGraph),
		EntityHeads:      entityHeads,
		RevisionGraph:    revisionGraph,
		ObjectRefs:       objectRefs,
	}

	if err := syncv2.SignCatalog(cat, devKeys); err != nil {
		return nil, err
	}
	return cat, nil
}

func (s *Store) decryptCatalogIntoVault(v *vault.Vault, cat *syncv2.Catalog, identity age.Identity) (int, error) {
	objectsDir := filepath.Join(s.cfg.SyncRepoDir, syncv2.ObjectsDir)
	decryptedCount := 0

	keys := make([]string, 0, len(cat.EntityHeads))
	for k := range cat.EntityHeads {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, entID := range keys {
		// Check if entity has unresolved conflict
		for _, cnf := range cat.Conflicts {
			if cnf.EntityID == entID && cnf.Status == conflict.StatusUnresolved {
				continue // Skip unresolved conflicted entity
			}
		}

		revID := cat.EntityHeads[entID]
		revNode := cat.RevisionGraph[revID]
		if revNode == nil {
			continue
		}

		if revNode.Deleted {
			ts := &model.Tombstone{
				EntityID:             entID,
				DeletedRevision:      revNode.RevisionNumber,
				DeletedAt:            revNode.CreatedAt,
				PreviousRevisionHash: revNode.SemanticRevisionHash,
			}
			_ = v.ApplyRemoteTombstone(ts)
			continue
		}

		opaqueID := model.ComputeFingerprint(model.KindMemory, model.ScopeGlobal, entID, revNode.SemanticRevisionHash, nil)[:24]
		objFile := filepath.Join(objectsDir, opaqueID+".age")
		ciphertext, err := os.ReadFile(objFile)
		if err != nil {
			continue
		}

		plaintext, err := crypt.Decrypt(identity, ciphertext)
		if err != nil {
			continue
		}

		v2Env := &model.EnvelopeV2{}
		if err := json.Unmarshal(plaintext, v2Env); err == nil && v2Env.SchemaVersion == model.SchemaVersionV2 {
			if err := v.SaveEntity(v2Env); err == nil {
				decryptedCount++
			}
		}
	}
	return decryptedCount, nil
}

func (s *Store) syncV1(ctx context.Context, v *vault.Vault, dryRun bool) (*SyncResult, error) {
	if dryRun {
		res := &SyncResult{
			Status: SyncStatusSuccess,
			DryRun: true,
		}
		if v != nil {
			artifacts := v.ListArtifacts()
			res.ObjectsEncryptedCount = len(artifacts)
		}
		return res, nil
	}

	if err := s.EnsureRepo(ctx); err != nil {
		return nil, err
	}

	validation := v.Validate()
	if !validation.Healthy {
		return nil, fmt.Errorf("refusing sync: local vault is unhealthy: %v", validation.Errors)
	}

	res := &SyncResult{DryRun: dryRun}
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

	if res.RemoteAhead && !dryRun {
		localRev, _ := s.execGit(ctx, "rev-parse", "HEAD")
		if localRev == "" {
			_, err := s.execGit(ctx, "checkout", "-B", "main", "origin/main")
			if err != nil {
				return nil, fmt.Errorf("failed checkout remote branch: %w", err)
			}
		} else if remoteURL != "" {
			_, err := s.execGit(ctx, "pull", "--ff-only", "origin", "main")
			if err != nil {
				return nil, fmt.Errorf("failed fast-forward pull: %w", err)
			}
		}
	}

	decryptedCount, err := s.decryptObjectsIntoVault(v)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting incoming remote objects: %w", err)
	}
	res.ObjectsDecryptedCount = decryptedCount

	manifestPath := filepath.Join(s.cfg.SyncRepoDir, "manifest.json")
	manifest := &Manifest{
		SchemaVersion: v.Metadata.SchemaVersion,
		VaultID:       v.Metadata.VaultID,
		UpdatedAt:     time.Now(),
		Objects:       make(map[string]*ManifestObject),
	}

	if data, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(data, manifest)
	}
	manifest.SchemaVersion = v.Metadata.SchemaVersion

	objectsDir := filepath.Join(s.cfg.SyncRepoDir, "objects")
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		return nil, err
	}

	vaultMetaBytes, err := json.MarshalIndent(v.Metadata, "", "  ")
	if err == nil {
		_ = fsutil.WriteFileAtomic(filepath.Join(s.cfg.SyncRepoDir, "vault.json"), vaultMetaBytes, 0600)
	}

	changedCount := 0
	entities := v.ListEntities()
	for _, env := range entities {
		if err := security.ValidateEnvelopeSecurity(env); err != nil {
			return nil, fmt.Errorf("security check failed during sync for V2 entity %s: %w", env.ID, err)
		}

		existingObj, exists := manifest.Objects[env.ID]
		if !exists || existingObj.Fingerprint != env.RevisionHash {
			portable := env.Clone()
			if portable.SourceRecord != nil {
				portable.SourceRecord.LocalPathRef = ""
			}

			envBytes, err := json.MarshalIndent(portable, "", "  ")
			if err != nil {
				return nil, err
			}

			ciphertext, err := crypt.Encrypt(v.Key.Recipient, envBytes)
			if err != nil {
				return nil, fmt.Errorf("failed encrypting V2 entity %s: %w", env.ID, err)
			}

			opaqueID := model.ComputeFingerprint(model.Kind(env.Kind), env.Scope, env.ID, env.RevisionHash, nil)[:24]
			objectFileName := opaqueID + ".age"
			objectPath := filepath.Join(objectsDir, objectFileName)

			if !dryRun {
				if err := fsutil.WriteFileAtomic(objectPath, ciphertext, 0600); err != nil {
					return nil, err
				}
				manifest.Objects[env.ID] = &ManifestObject{
					OpaqueID:      opaqueID,
					Fingerprint:   env.RevisionHash,
					EncryptedSize: int64(len(ciphertext)),
					UpdatedAt:     time.Now(),
				}
			}
			changedCount++
		}
	}

	artifacts := v.ListArtifacts()
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

	if tombstones, err := v.ListTombstones(); err == nil {
		for _, ts := range tombstones {
			existingObj, exists := manifest.Objects[ts.EntityID]
			if !exists || !existingObj.IsTombstone {
				opaqueID := model.ComputeFingerprint(model.KindMemory, model.ScopeGlobal, ts.EntityID, "tombstone", nil)[:24]
				manifest.Objects[ts.EntityID] = &ManifestObject{
					OpaqueID:             opaqueID,
					Fingerprint:          ts.PreviousRevisionHash,
					UpdatedAt:            ts.DeletedAt,
					IsTombstone:          true,
					DeletedRevision:      ts.DeletedRevision,
					OriginMachineID:      ts.OriginMachineID,
					PreviousRevisionHash: ts.PreviousRevisionHash,
				}
				changedCount++
			}
		}
	}

	res.ObjectsEncryptedCount = changedCount

	if dryRun {
		res.Status = SyncStatusSuccess
		res.Message = "Sync dry-run completed successfully"
		return res, nil
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := fsutil.WriteFileAtomic(manifestPath, manifestBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed saving manifest: %w", err)
	}

	if _, err := s.execGit(ctx, "add", "-A"); err != nil {
		return nil, fmt.Errorf("failed git add: %w", err)
	}

	hasStaged, err := s.hasAnyStagedChanges(ctx)
	if err != nil {
		return nil, err
	}

	if !hasStaged {
		res.Status = SyncStatusSuccess
		res.Message = "Vault already fully in sync"
		return res, nil
	}

	commitMsg := fmt.Sprintf("sync: vault state updated (%s)", time.Now().Format(time.RFC3339))
	sha, err := s.execGit(ctx, "commit", "-m", commitMsg)
	if err != nil {
		return nil, fmt.Errorf("failed git commit: %w", err)
	}
	res.CommitSHA = sha

	if remoteURL != "" {
		_, err := s.execGit(ctx, "push", "origin", "main")
		if err != nil {
			res.Status = SyncStatusPushFailed
			res.Message = fmt.Sprintf("commit succeeded locally (%s), but push to origin main failed: %v", sha, err)
			return res, nil
		}
	}

	res.Status = SyncStatusSuccess
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
		if obj.IsTombstone {
			ts := &model.Tombstone{
				EntityID:             artID,
				DeletedRevision:      obj.DeletedRevision,
				DeletedAt:            obj.UpdatedAt,
				OriginMachineID:      obj.OriginMachineID,
				PreviousRevisionHash: obj.PreviousRevisionHash,
			}
			if ts.PreviousRevisionHash == "" {
				ts.PreviousRevisionHash = obj.Fingerprint
			}
			if ts.DeletedRevision < 1 {
				ts.DeletedRevision = 1
			}
			_ = v.ApplyRemoteTombstone(ts)
			continue
		}
		if _, isTomb := v.GetTombstone(artID); isTomb {
			continue
		}
		objFile := filepath.Join(objectsDir, obj.OpaqueID+".age")
		ciphertext, err := os.ReadFile(objFile)
		if err != nil {
			continue
		}

		plaintext, err := crypt.Decrypt(v.Key.Identity, ciphertext)
		if err != nil {
			return decryptedCount, fmt.Errorf("failed decrypting object %s: %w", obj.OpaqueID, err)
		}

		v2Env := &model.EnvelopeV2{}
		if err := json.Unmarshal(plaintext, v2Env); err == nil && v2Env.SchemaVersion == model.SchemaVersionV2 {
			if err := v.SaveEntity(v2Env); err != nil {
				return decryptedCount, fmt.Errorf("failed saving decrypted V2 entity %s to vault: %w", v2Env.ID, err)
			}
			decryptedCount++
			continue
		}

		art := &model.Artifact{}
		if err := json.Unmarshal(plaintext, art); err != nil {
			return decryptedCount, fmt.Errorf("failed parsing decrypted artifact for %s: %w", artID, err)
		}

		if err := v.SaveArtifact(art); err != nil {
			return decryptedCount, fmt.Errorf("failed saving decrypted artifact to vault for %s: %w", artID, err)
		}
		decryptedCount++
	}

	return decryptedCount, nil
}

func (s *Store) hasAnyStagedChanges(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet")
	cmd.Dir = s.cfg.SyncRepoDir
	err := cmd.Run()
	if err == nil {
		revOut, revErr := s.execGit(ctx, "rev-parse", "--verify", "HEAD")
		if revErr != nil || revOut == "" {
			out, serr := s.execGit(ctx, "status", "--porcelain")
			if serr != nil {
				return false, serr
			}
			return len(strings.TrimSpace(out)) > 0, nil
		}
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, fmt.Errorf("git diff --cached --quiet failed unexpectedly: %w", err)
}
