package syncv2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/revision"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type MigrationStatus struct {
	AlreadyMigrated bool      `json:"already_migrated"`
	DeviceID        string    `json:"device_id,omitempty"`
	VaultID         string    `json:"vault_id,omitempty"`
	RegistryEpoch   uint64    `json:"registry_epoch"`
	ActiveDevices   int       `json:"active_devices"`
	CatalogID       string    `json:"catalog_id,omitempty"`
	MigratedAt      time.Time `json:"migrated_at,omitempty"`
}

// CheckMigrationStatus returns current V2 protocol migration status.
func CheckMigrationStatus(cfg *config.Config) (*MigrationStatus, error) {
	meta, err := ReadProtocolMetadata(cfg.SyncRepoDir)
	if err != nil {
		return &MigrationStatus{AlreadyMigrated: false}, nil
	}
	if meta.ProtocolVersion == "2.0" {
		devKeys, _ := device.LoadDeviceKeys(cfg)
		devID := ""
		if devKeys != nil {
			devID = devKeys.DeviceID
		}
		return &MigrationStatus{
			AlreadyMigrated: true,
			DeviceID:        devID,
			VaultID:         meta.VaultID,
			RegistryEpoch:   meta.RegistryEpoch,
			CatalogID:       meta.CatalogHeadID,
		}, nil
	}
	return &MigrationStatus{AlreadyMigrated: false}, nil
}

// MigrateToV2 performs atomic, fail-closed migration from Phase 5 to Phase 6 Sync Protocol V2.
func MigrateToV2(ctx context.Context, cfg *config.Config, v *vault.Vault, dryRun bool) (*MigrationStatus, error) {
	status, err := CheckMigrationStatus(cfg)
	if err == nil && status.AlreadyMigrated {
		return status, nil
	}

	if dryRun {
		return &MigrationStatus{
			AlreadyMigrated: false,
			VaultID:         v.Metadata.VaultID,
			RegistryEpoch:   1,
			ActiveDevices:   1,
		}, nil
	}

	// 1. Create safety snapshot before migration
	snapMgr := snapshot.NewManager(cfg)
	if _, err := snapMgr.CreateSnapshot(v, "Pre-Phase 6 Protocol V2 Migration"); err != nil {
		return nil, fmt.Errorf("failed creating safety snapshot before migration: %w", err)
	}

	// 2. Load or bootstrap device keys
	devKeys, err := device.LoadDeviceKeys(cfg)
	if err != nil {
		// Convert existing Age identity into Device A's identity
		agePath := filepath.Join(cfg.KeysDir, "identity.age")
		var ageKp *crypt.KeyPair
		if _, statErr := os.Stat(agePath); err == nil && statErr == nil {
			ageKp, _ = crypt.LoadIdentityFromFile(agePath)
		}
		if ageKp == nil {
			ageKp = v.Key
		}

		genKeys, genErr := device.GenerateDeviceKeys("Initial Authorized Device")
		if genErr != nil {
			return nil, fmt.Errorf("failed generating initial device keys: %w", genErr)
		}
		// Retain existing Age key identity
		genKeys.AgeIdentity = ageKp.Identity
		genKeys.AgeRecipient = ageKp.Recipient.String()
		devKeys = genKeys

		if err := device.SaveDeviceKeys(cfg, devKeys); err != nil {
			return nil, fmt.Errorf("failed saving initial device keys: %w", err)
		}
	}

	// 3. Generate Recovery Authority
	recAuth, err := device.GenerateRecoveryAuthority()
	if err != nil {
		return nil, fmt.Errorf("failed generating recovery authority: %w", err)
	}
	if err := device.SaveRecoveryPublicConfig(cfg, recAuth); err != nil {
		return nil, fmt.Errorf("failed saving recovery public config: %w", err)
	}

	// 4. Initialize revision store
	revStoreDir := filepath.Join(cfg.VaultDir, "revisions")
	revStore, err := revision.NewStore(revStoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed initializing revision store: %w", err)
	}

	// 5. Bootstrap RevisionRecords for all current entities
	entities := v.ListEntities()
	revisionGraph := make(map[string]*revision.RevisionRecord)
	entityHeads := make(map[string]string)

	recip1, _ := device.GetRecipientFromRecipientString(devKeys.AgeRecipient)
	recip2, _ := device.GetRecipientFromRecipientString(recAuth.AgeRecipient)
	activeRecipients := []age.Recipient{recip1, recip2}

	objectsDir := filepath.Join(cfg.SyncRepoDir, ObjectsDir)
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		return nil, err
	}

	objectRefs := make(map[string]*ObjectRefInfo)

	for _, env := range entities {
		revID := revision.GenerateRevisionID()
		revNum := env.Revision
		if revNum < 1 {
			revNum = 1
		}
		revRecord := &revision.RevisionRecord{
			RevisionID:           revID,
			EntityID:             env.ID,
			RevisionNumber:       revNum,
			SemanticRevisionHash: env.RevisionHash,
			AuthorDeviceID:       devKeys.DeviceID,
			CreatedAt:            env.CreatedAt,
		}

		if err := revStore.SaveRevision(revRecord); err != nil {
			return nil, fmt.Errorf("failed saving bootstrap revision for %s: %w", env.ID, err)
		}

		revisionGraph[revID] = revRecord
		entityHeads[env.ID] = revID

		// Encrypt entity object for active recipient set
		portable := env.Clone()
		if portable.SourceRecord != nil {
			portable.SourceRecord.LocalPathRef = ""
		}

		envBytes, err := json.MarshalIndent(portable, "", "  ")
		if err != nil {
			return nil, err
		}

		ciphertext, err := crypt.EncryptToRecipients(activeRecipients, envBytes)
		if err != nil {
			return nil, fmt.Errorf("failed encrypting entity %s: %w", env.ID, err)
		}

		opaqueID := model.ComputeFingerprint(model.Kind(env.Kind), env.Scope, env.ID, env.RevisionHash, nil)[:24]
		objFileName := opaqueID + ".age"
		objPath := filepath.Join(objectsDir, objFileName)

		if err := fsutil.WriteFileAtomic(objPath, ciphertext, 0600); err != nil {
			return nil, fmt.Errorf("failed saving object file %s: %w", objFileName, err)
		}

		cSum := device.ComputePayloadHash(ciphertext)
		objectRefs[objFileName] = &ObjectRefInfo{
			OpaqueObjectID:       opaqueID,
			CiphertextSHA256:     cSum,
			SemanticRevisionHash: env.RevisionHash,
			RevisionID:           revID,
			EntityID:             env.ID,
			EncryptionEpoch:      1,
		}
	}

	// Bootstrap tombstones
	tombstoneIDs := make([]string, 0)
	if tombstones, err := v.ListTombstones(); err == nil {
		for _, ts := range tombstones {
			tombstoneIDs = append(tombstoneIDs, ts.EntityID)
			revID := revision.GenerateRevisionID()
			revRecord := &revision.RevisionRecord{
				RevisionID:           revID,
				EntityID:             ts.EntityID,
				RevisionNumber:       ts.DeletedRevision,
				SemanticRevisionHash: ts.PreviousRevisionHash,
				AuthorDeviceID:       devKeys.DeviceID,
				CreatedAt:            ts.DeletedAt,
				Deleted:              true,
			}
			_ = revStore.SaveRevision(revRecord)
			revisionGraph[revID] = revRecord
			entityHeads[ts.EntityID] = revID
		}
	}

	// 6. Create Registry Epoch 1
	epoch1 := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         v.Metadata.VaultID,
		Epoch:           1,
		ActiveDevices: map[string]*device.DeviceRecord{
			devKeys.DeviceID: {
				DeviceID:         devKeys.DeviceID,
				AgeRecipient:     devKeys.AgeRecipient,
				SigningPublicKey: devKeys.SigningPublicKeyHex,
				Status:           device.StatusActive,
				AddedEpoch:       1,
				CreatedAt:        time.Now().UTC(),
			},
		},
		SignerDeviceID: devKeys.DeviceID,
		CreatedAt:      time.Now().UTC(),
	}

	if err := device.SignRegistry(epoch1, devKeys); err != nil {
		return nil, fmt.Errorf("failed signing registry epoch 1: %w", err)
	}

	regHash1, err := device.ComputeRegistryHash(epoch1)
	if err != nil {
		return nil, err
	}

	// Write registry epoch 1 file
	if err := EnsureRepoStructure(cfg.SyncRepoDir); err != nil {
		return nil, err
	}

	epoch1Bytes, _ := json.MarshalIndent(epoch1, "", "  ")
	epoch1Path := filepath.Join(cfg.SyncRepoDir, RegistryDir, "epoch-000001.json")
	if err := fsutil.WriteFileAtomic(epoch1Path, epoch1Bytes, 0600); err != nil {
		return nil, err
	}

	regHeadPath := filepath.Join(cfg.SyncRepoDir, RegistryHeadFile)
	if err := fsutil.WriteFileAtomic(regHeadPath, epoch1Bytes, 0600); err != nil {
		return nil, err
	}

	// Save Local Trust Anchor
	trust := &device.LocalTrustAnchor{
		VaultID:              v.Metadata.VaultID,
		HighestRegistryEpoch: 1,
		RegistryHeadHash:     regHash1,
	}
	if err := device.SaveTrustAnchor(cfg, trust); err != nil {
		return nil, fmt.Errorf("failed saving trust anchor: %w", err)
	}

	// 7. Create Initial Signed Catalog
	cat1 := &Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          v.Metadata.VaultID,
		CatalogID:        GenerateCatalogID(),
		RegistryEpoch:    1,
		RegistryHash:     regHash1,
		RecipientSetHash: crypt.RecipientSetHash([]string{devKeys.AgeRecipient, recAuth.AgeRecipient}),
		CreatedAt:        time.Now().UTC(),
		WriterDeviceID:   devKeys.DeviceID,
		StateRoot:        ComputeStateRoot(entityHeads, revisionGraph),
		EntityHeads:      entityHeads,
		RevisionGraph:    revisionGraph,
		ObjectRefs:       objectRefs,
		Tombstones:       tombstoneIDs,
	}

	if err := SignCatalog(cat1, devKeys); err != nil {
		return nil, fmt.Errorf("failed signing initial catalog: %w", err)
	}

	catBytes, err := EncryptCatalog(cat1, activeRecipients)
	if err != nil {
		return nil, fmt.Errorf("failed encrypting initial catalog: %w", err)
	}

	catFileName := cat1.CatalogID + ".age"
	catPath := filepath.Join(cfg.SyncRepoDir, CatalogsDir, catFileName)
	if err := fsutil.WriteFileAtomic(catPath, catBytes, 0600); err != nil {
		return nil, err
	}

	catHeadData := map[string]string{
		"catalog_id": cat1.CatalogID,
		"file":       filepath.Join(CatalogsDir, catFileName),
	}
	catHeadBytes, _ := json.MarshalIndent(catHeadData, "", "  ")
	if err := fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, CatalogHeadFile), catHeadBytes, 0600); err != nil {
		return nil, err
	}

	// Update trust anchor with catalog ID
	trust.LastAcceptedCatalogID = cat1.CatalogID
	_ = device.SaveTrustAnchor(cfg, trust)

	// 8. Write protocol.json
	meta := &ProtocolMetadata{
		ProtocolVersion:  "2.0",
		VaultID:          v.Metadata.VaultID,
		RegistryHeadHash: regHash1,
		RegistryEpoch:    1,
		CatalogHeadID:    cat1.CatalogID,
	}
	if err := WriteProtocolMetadata(cfg.SyncRepoDir, meta); err != nil {
		return nil, err
	}

	// 9. Remove obsolete legacy V1 manifest.json if present
	_ = os.Remove(filepath.Join(cfg.SyncRepoDir, "manifest.json"))

	resStatus := &MigrationStatus{
		AlreadyMigrated: true,
		DeviceID:        devKeys.DeviceID,
		VaultID:         v.Metadata.VaultID,
		RegistryEpoch:   1,
		ActiveDevices:   1,
		CatalogID:       cat1.CatalogID,
		MigratedAt:      time.Now().UTC(),
	}

	return resStatus, nil
}
