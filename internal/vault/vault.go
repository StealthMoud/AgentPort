package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/security"
)

var (
	ErrVaultNotInitialized  = errors.New("vault is not initialized (run 'agentport init' first)")
	ErrArtifactNotFound     = errors.New("artifact not found in vault")
	ErrVaultCorrupted       = errors.New("vault state corrupted")
	ErrRecipientKeyMismatch = errors.New("key recipient does not match vault recipient")
)

type VaultMetadata struct {
	VaultID       string    `json:"vault_id"`
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	Recipient     string    `json:"recipient"`
	FormatVersion string    `json:"format_version"`
}

type MachineMetadata struct {
	MachineID string    `json:"machine_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Vault struct {
	mu        sync.RWMutex
	cfg       *config.Config
	Metadata  *VaultMetadata
	Machine   *MachineMetadata
	Key       *crypt.KeyPair
	artifacts map[string]*model.Artifact
	entities  map[string]*model.EnvelopeV2
}

// GenerateID generates a random hex identifier with a prefix (e.g. apv_... or apm_...).
func GenerateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// Initialize creates a new vault if not already initialized.
func Initialize(cfg *config.Config) (*Vault, error) {
	if err := cfg.EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed creating directories: %w", err)
	}

	keyPath := filepath.Join(cfg.KeysDir, "identity.age")
	var kp *crypt.KeyPair
	var err error

	if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
		kp, err = crypt.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		if err := crypt.SaveIdentityToFile(kp.Identity, keyPath); err != nil {
			return nil, fmt.Errorf("failed saving encryption identity: %w", err)
		}
	} else {
		kp, err = crypt.LoadIdentityFromFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed loading encryption identity: %w", err)
		}
	}

	vaultMetaPath := filepath.Join(cfg.VaultDir, "vault.json")
	var vaultMeta *VaultMetadata
	if _, statErr := os.Stat(vaultMetaPath); os.IsNotExist(statErr) {
		vaultMeta = &VaultMetadata{
			VaultID:       GenerateID("apv"),
			SchemaVersion: model.SchemaVersionV1,
			CreatedAt:     time.Now(),
			Recipient:     kp.Recipient.String(),
			FormatVersion: "1",
		}
		data, err := json.MarshalIndent(vaultMeta, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(vaultMetaPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed saving vault metadata: %w", err)
		}
	} else {
		data, err := os.ReadFile(vaultMetaPath)
		if err != nil {
			return nil, err
		}
		vaultMeta = &VaultMetadata{}
		if err := json.Unmarshal(data, vaultMeta); err != nil {
			return nil, fmt.Errorf("failed parsing vault metadata: %w", err)
		}
		if vaultMeta.Recipient != "" && kp.Recipient != nil {
			if vaultMeta.Recipient != kp.Recipient.String() {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrRecipientKeyMismatch, vaultMeta.Recipient, kp.Recipient.String())
			}
		}
	}

	machineMetaPath := filepath.Join(cfg.HomeDir, "machine.json")
	var machineMeta *MachineMetadata
	if _, statErr := os.Stat(machineMetaPath); os.IsNotExist(statErr) {
		machineMeta = &MachineMetadata{
			MachineID: GenerateID("apm"),
			CreatedAt: time.Now(),
		}
		data, err := json.MarshalIndent(machineMeta, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(machineMetaPath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed saving machine metadata: %w", err)
		}
	} else {
		data, err := os.ReadFile(machineMetaPath)
		if err != nil {
			return nil, err
		}
		machineMeta = &MachineMetadata{}
		if err := json.Unmarshal(data, machineMeta); err != nil {
			return nil, fmt.Errorf("failed parsing machine metadata: %w", err)
		}
	}

	v := &Vault{
		cfg:       cfg,
		Metadata:  vaultMeta,
		Machine:   machineMeta,
		Key:       kp,
		artifacts: make(map[string]*model.Artifact),
		entities:  make(map[string]*model.EnvelopeV2),
	}

	if err := v.LoadAll(); err != nil {
		return nil, err
	}

	return v, nil
}

// LoadOpen loads an existing vault without reinitializing if missing.
func LoadOpen(cfg *config.Config) (*Vault, error) {
	vaultMetaPath := filepath.Join(cfg.VaultDir, "vault.json")
	if _, err := os.Stat(vaultMetaPath); os.IsNotExist(err) {
		return nil, ErrVaultNotInitialized
	}
	return Initialize(cfg)
}

// LoadAll loads all local decrypted artifacts and V2 entities from disk.
func (v *Vault) LoadAll() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	artifactsDir := filepath.Join(v.cfg.VaultDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return err
	}

	entries, err := os.ReadDir(artifactsDir)
	if err != nil {
		return err
	}

	v.artifacts = make(map[string]*model.Artifact)
	v.entities = make(map[string]*model.EnvelopeV2)

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(artifactsDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed reading artifact %s: %w", entry.Name(), err)
		}

		// Try parsing as V2 Envelope first
		v2Env := &model.EnvelopeV2{}
		if err := json.Unmarshal(data, v2Env); err == nil && v2Env.SchemaVersion == model.SchemaVersionV2 {
			v.entities[v2Env.ID] = v2Env
			continue
		}

		art := &model.Artifact{}
		if err := json.Unmarshal(data, art); err != nil {
			return fmt.Errorf("failed parsing artifact %s: %w", entry.Name(), err)
		}

		v.artifacts[art.ID] = art
	}

	return nil
}

// SaveEntity validates and persists a V2 envelope to local storage.
func (v *Vault) SaveEntity(env *model.EnvelopeV2) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if env.SchemaVersion == "" {
		env.SchemaVersion = model.SchemaVersionV2
	}
	if env.Revision < 1 {
		env.Revision = 1
	}

	if err := env.Validate(); err != nil {
		return err
	}

	if err := security.ValidateEnvelopeSecurity(env); err != nil {
		return err
	}

	if env.CreatedAt.IsZero() {
		env.CreatedAt = time.Now()
	}
	env.UpdatedAt = time.Now()

	artifactsDir := filepath.Join(v.cfg.VaultDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	artPath := filepath.Join(artifactsDir, env.ID+".json")
	if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
		return err
	}

	v.entities[env.ID] = env
	return nil
}

// GetEntity retrieves a V2 envelope by ID.
func (v *Vault) GetEntity(id string) (*model.EnvelopeV2, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	env, exists := v.entities[id]
	if !exists {
		return nil, false
	}
	return env, true
}

// ListEntities returns a slice of all current V2 envelopes.
func (v *Vault) ListEntities() []*model.EnvelopeV2 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	res := make([]*model.EnvelopeV2, 0, len(v.entities))
	for _, env := range v.entities {
		res = append(res, env)
	}
	return res
}

// DeleteEntity deletes a V2 envelope by ID and creates a tombstone.
func (v *Vault) DeleteEntity(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var prevHash string
	if env, ok := v.entities[id]; ok {
		prevHash = env.RevisionHash
	}

	artPath := filepath.Join(v.cfg.VaultDir, "artifacts", id+".json")
	_ = os.Remove(artPath)
	delete(v.entities, id)

	tombDir := filepath.Join(v.cfg.VaultDir, "tombstones")
	_ = os.MkdirAll(tombDir, 0700)
	ts := &model.Tombstone{
		EntityID:             id,
		DeletedRevision:      1,
		DeletedAt:            time.Now(),
		OriginMachineID:      v.Machine.MachineID,
		PreviousRevisionHash: prevHash,
	}
	data, _ := json.MarshalIndent(ts, "", "  ")
	_ = fsutil.WriteFileAtomic(filepath.Join(tombDir, id+".json"), data, 0600)

	return nil
}

// UpdateEntity updates an existing V2 envelope, preserving entity ID and incrementing Revision (N -> N+1).
func (v *Vault) UpdateEntity(env *model.EnvelopeV2) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	existing, exists := v.entities[env.ID]
	if !exists {
		return fmt.Errorf("entity %s not found for update", env.ID)
	}

	env.Revision = existing.Revision + 1
	env.UpdatedAt = time.Now()

	if err := env.Validate(); err != nil {
		return err
	}

	if err := security.ValidateEnvelopeSecurity(env); err != nil {
		return err
	}

	artifactsDir := filepath.Join(v.cfg.VaultDir, "artifacts")
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	artPath := filepath.Join(artifactsDir, env.ID+".json")
	if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
		return err
	}

	v.entities[env.ID] = env
	return nil
}

// SaveArtifact validates, security scans, and persists an artifact to local decrypted storage.
func (v *Vault) SaveArtifact(art *model.Artifact) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	art.UpdateFingerprint()

	if art.ID == "" {
		art.ID = model.GenerateArtifactID(art.Kind, art.Fingerprint)
	}

	if err := art.Validate(); err != nil {
		return err
	}

	if err := security.ValidateArtifactSecurity(art); err != nil {
		return err
	}

	if art.CreatedAt.IsZero() {
		art.CreatedAt = time.Now()
	}
	art.UpdatedAt = time.Now()

	artifactsDir := filepath.Join(v.cfg.VaultDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0700); err != nil {
		return err
	}

	artPath := filepath.Join(artifactsDir, art.ID+".json")
	data, err := json.MarshalIndent(art, "", "  ")
	if err != nil {
		return err
	}

	if err := fsutil.WriteFileAtomic(artPath, data, 0600); err != nil {
		return err
	}

	v.artifacts[art.ID] = art.Clone()
	return nil
}

// GetArtifact retrieves a deep copy of an artifact by ID.
func (v *Vault) GetArtifact(id string) (*model.Artifact, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	art, exists := v.artifacts[id]
	if !exists {
		return nil, false
	}
	return art.Clone(), true
}

// GetArtifactCopy retrieves a deep copy of an artifact by ID.
func (v *Vault) GetArtifactCopy(id string) (*model.Artifact, bool) {
	return v.GetArtifact(id)
}

// ListArtifacts returns a slice of deep copies of all current local artifacts.
func (v *Vault) ListArtifacts() []*model.Artifact {
	v.mu.RLock()
	defer v.mu.RUnlock()

	res := make([]*model.Artifact, 0, len(v.artifacts))
	for _, art := range v.artifacts {
		res = append(res, art.Clone())
	}
	return res
}

// ListArtifactCopies returns a slice of deep copies of all current local artifacts.
func (v *Vault) ListArtifactCopies() []*model.Artifact {
	return v.ListArtifacts()
}

// DeleteArtifact deletes artifact by ID and records a tombstone.
func (v *Vault) DeleteArtifact(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var prevHash string
	if art, ok := v.artifacts[id]; ok {
		prevHash = art.Fingerprint
	}

	artPath := filepath.Join(v.cfg.VaultDir, "artifacts", id+".json")
	_ = os.Remove(artPath)
	delete(v.artifacts, id)

	tombDir := filepath.Join(v.cfg.VaultDir, "tombstones")
	_ = os.MkdirAll(tombDir, 0700)
	ts := &model.Tombstone{
		EntityID:             id,
		DeletedRevision:      1,
		DeletedAt:            time.Now(),
		OriginMachineID:      v.Machine.MachineID,
		PreviousRevisionHash: prevHash,
	}
	data, _ := json.MarshalIndent(ts, "", "  ")
	_ = fsutil.WriteFileAtomic(filepath.Join(tombDir, id+".json"), data, 0600)

	return nil
}
