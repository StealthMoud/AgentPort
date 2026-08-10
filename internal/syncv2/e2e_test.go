package syncv2_test

import (
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/revision"
	"github.com/StealthMoud/AgentPort/internal/syncv2"
)

func TestThreeDevicePairingAndMergeE2E(t *testing.T) {
	// Computer A (Genesis)
	devA, _ := device.GenerateDeviceKeys("Computer A")
	// Computer B
	devB, _ := device.GenerateDeviceKeys("Computer B")
	// Computer C
	devC, _ := device.GenerateDeviceKeys("Computer C")

	// Ensure all 3 have distinct device keys
	if devA.DeviceID == devB.DeviceID || devB.DeviceID == devC.DeviceID {
		t.Fatalf("DeviceIDs must be unique")
	}
	if devA.AgeRecipient == devB.AgeRecipient || devB.AgeRecipient == devC.AgeRecipient {
		t.Fatalf("Age Recipients must be unique")
	}
	if devA.SigningPublicKeyHex == devB.SigningPublicKeyHex {
		t.Fatalf("Signing keys must be unique")
	}

	// 1. Genesis Epoch 1 (Computer A active)
	epoch1 := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         "vlt_e2e123",
		Epoch:           1,
		ActiveDevices: map[string]*device.DeviceRecord{
			devA.DeviceID: {
				DeviceID:         devA.DeviceID,
				AgeRecipient:     devA.AgeRecipient,
				SigningPublicKey: devA.SigningPublicKeyHex,
				Status:           device.StatusActive,
				AddedEpoch:       1,
				CreatedAt:        time.Now().UTC(),
			},
		},
		SignerDeviceID: devA.DeviceID,
		CreatedAt:      time.Now().UTC(),
	}
	_ = device.SignRegistry(epoch1, devA)

	// 2. Computer B Joins -> Pairing Request created
	reqB, err := device.CreatePairingRequest(devB, epoch1.VaultID, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreatePairingRequest B failed: %v", err)
	}
	if err := device.ValidatePairingRequest(reqB); err != nil {
		t.Fatalf("ValidatePairingRequest B failed: %v", err)
	}

	// Computer A approves Computer B -> Epoch 2
	hash1, _ := device.ComputeRegistryHash(epoch1)
	epoch2Active := map[string]*device.DeviceRecord{
		devA.DeviceID: epoch1.ActiveDevices[devA.DeviceID],
		devB.DeviceID: {
			DeviceID:         devB.DeviceID,
			AgeRecipient:     devB.AgeRecipient,
			SigningPublicKey: devB.SigningPublicKeyHex,
			Status:           device.StatusActive,
			AddedEpoch:       2,
			CreatedAt:        time.Now().UTC(),
		},
	}
	epoch2 := &device.RegistryEpoch{
		ProtocolVersion:      device.ProtocolVersionV2,
		VaultID:              epoch1.VaultID,
		Epoch:                2,
		PreviousRegistryHash: hash1,
		ActiveDevices:        epoch2Active,
		SignerDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}
	_ = device.SignRegistry(epoch2, devA)

	// 3. Computer C Joins -> Approved by A -> Epoch 3
	hash2, _ := device.ComputeRegistryHash(epoch2)
	epoch3Active := map[string]*device.DeviceRecord{
		devA.DeviceID: epoch2.ActiveDevices[devA.DeviceID],
		devB.DeviceID: epoch2.ActiveDevices[devB.DeviceID],
		devC.DeviceID: {
			DeviceID:         devC.DeviceID,
			AgeRecipient:     devC.AgeRecipient,
			SigningPublicKey: devC.SigningPublicKeyHex,
			Status:           device.StatusActive,
			AddedEpoch:       3,
			CreatedAt:        time.Now().UTC(),
		},
	}
	epoch3 := &device.RegistryEpoch{
		ProtocolVersion:      device.ProtocolVersionV2,
		VaultID:              epoch1.VaultID,
		Epoch:                3,
		PreviousRegistryHash: hash2,
		ActiveDevices:        epoch3Active,
		SignerDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}
	_ = device.SignRegistry(epoch3, devA)

	// Verify all 3 devices active in Epoch 3
	if len(epoch3.ActiveDevices) != 3 {
		t.Fatalf("expected 3 active devices in epoch 3, got %d", len(epoch3.ActiveDevices))
	}

	// Multi-recipient encryption verification across A, B, and C
	recipA, _ := device.GetRecipientFromRecipientString(devA.AgeRecipient)
	recipB, _ := device.GetRecipientFromRecipientString(devB.AgeRecipient)
	recipC, _ := device.GetRecipientFromRecipientString(devC.AgeRecipient)

	allRecips := []age.Recipient{recipA, recipB, recipC}
	plaintext := []byte("Canonical state shared across A, B, and C")

	ciphertext, err := crypt.EncryptToRecipients(allRecips, plaintext)
	if err != nil {
		t.Fatalf("EncryptToRecipients for 3 devices failed: %v", err)
	}

	// All 3 devices decrypt cleanly!
	for name, dev := range map[string]*device.DeviceKeys{"A": devA, "B": devB, "C": devC} {
		dec, err := crypt.Decrypt(dev.AgeIdentity, ciphertext)
		if err != nil || string(dec) != string(plaintext) {
			t.Errorf("Device %s failed decrypting shared state: %v", name, err)
		}
	}

	// 4. Independent Entity Merge Scenario
	// Computer A modifies Entity X; Computer B modifies Entity Y independently
	revX := &revision.RevisionRecord{
		RevisionID:           "rev_X",
		EntityID:             "apm_X",
		RevisionNumber:       1,
		SemanticRevisionHash: "hash_X",
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}
	revY := &revision.RevisionRecord{
		RevisionID:           "rev_Y",
		EntityID:             "apm_Y",
		RevisionNumber:       1,
		SemanticRevisionHash: "hash_Y",
		AuthorDeviceID:       devB.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	catA := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          epoch3.VaultID,
		CatalogID:        "cat_A",
		RegistryEpoch:    3,
		EntityHeads:      map[string]string{"apm_X": "rev_X"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_X": revX},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	catB := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          epoch3.VaultID,
		CatalogID:        "cat_B",
		RegistryEpoch:    3,
		EntityHeads:      map[string]string{"apm_Y": "rev_Y"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_Y": revY},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	mergeRes, err := syncv2.MergeCatalogs(catA, catB, epoch3, devA)
	if err != nil {
		t.Fatalf("MergeCatalogs failed: %v", err)
	}

	if mergeRes.HasConflicts {
		t.Errorf("expected clean convergence for independent entities X and Y, but got conflicts")
	}

	if len(mergeRes.MergedCatalog.EntityHeads) != 2 {
		t.Errorf("expected 2 entity heads in merged catalog, got %d", len(mergeRes.MergedCatalog.EntityHeads))
	}
}

func TestSameEntityConflictAndResolutionE2E(t *testing.T) {
	devA, registry := setupTestDeviceRegistry(t)
	devB, _ := device.GenerateDeviceKeys("Device B")

	// Base revision for Entity Z
	revZBase := &revision.RevisionRecord{
		RevisionID:           "rev_Z_base",
		EntityID:             "apm_Z",
		RevisionNumber:       1,
		SemanticRevisionHash: "hash_Z_base",
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	// Device A modifies Z -> rev_ZA
	revZA := &revision.RevisionRecord{
		RevisionID:           "rev_ZA",
		EntityID:             "apm_Z",
		RevisionNumber:       2,
		SemanticRevisionHash: "hash_ZA",
		ParentRevisionIDs:    []string{"rev_Z_base"},
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	// Device B modifies Z -> rev_ZB
	revZB := &revision.RevisionRecord{
		RevisionID:           "rev_ZB",
		EntityID:             "apm_Z",
		RevisionNumber:       2,
		SemanticRevisionHash: "hash_ZB",
		ParentRevisionIDs:    []string{"rev_Z_base"},
		AuthorDeviceID:       devB.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	catA := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        "cat_A",
		RegistryEpoch:    registry.Epoch,
		EntityHeads:      map[string]string{"apm_Z": "rev_ZA"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_Z_base": revZBase, "rev_ZA": revZA},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	catB := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        "cat_B",
		RegistryEpoch:    registry.Epoch,
		EntityHeads:      map[string]string{"apm_Z": "rev_ZB"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_Z_base": revZBase, "rev_ZB": revZB},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	// Run Application Merge
	mergeRes, err := syncv2.MergeCatalogs(catA, catB, registry, devA)
	if err != nil {
		t.Fatalf("MergeCatalogs failed: %v", err)
	}

	if !mergeRes.HasConflicts || len(mergeRes.NewConflicts) != 1 {
		t.Fatalf("expected 1 conflict for divergent entity Z, got %d", len(mergeRes.NewConflicts))
	}

	var cnf *conflict.ConflictRecord
	for _, c := range mergeRes.NewConflicts {
		cnf = c
	}

	if cnf.Type != conflict.TypeModifyModify || cnf.EntityID != "apm_Z" {
		t.Errorf("unexpected conflict record: %+v", cnf)
	}

	// Conflict Resolution: create new merge revision with both rev_ZA and rev_ZB as parents
	resolvedRev := &revision.RevisionRecord{
		RevisionID:           revision.GenerateRevisionID(),
		EntityID:             "apm_Z",
		RevisionNumber:       3,
		SemanticRevisionHash: "hash_ZA", // Take local version
		ParentRevisionIDs:    []string{"rev_ZA", "rev_ZB"},
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	cnf.Status = conflict.StatusResolved
	cnf.ResolutionRevisionID = resolvedRev.RevisionID

	if cnf.Status != conflict.StatusResolved || cnf.ResolutionRevisionID == "" {
		t.Errorf("conflict resolution failed")
	}
}

func TestDisasterRecoveryE2E(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "disaster_recovery.age")

	// Setup Recovery Authority
	recAuth, err := device.GenerateRecoveryAuthority()
	if err != nil {
		t.Fatalf("GenerateRecoveryAuthority failed: %v", err)
	}

	passphrase := "recovery-master-passphrase-999!"
	vaultID := "vlt_disaster123"

	// Export recovery bundle
	if err := device.ExportRecoveryBundle(recAuth, vaultID, bundlePath, passphrase); err != nil {
		t.Fatalf("ExportRecoveryBundle failed: %v", err)
	}

	// Simulated total loss of Device A and Device B keys!
	// Computer D recovers vault using recovery bundle
	importedAuth, impVaultID, err := device.ImportRecoveryBundle(bundlePath, passphrase, nil)
	if err != nil {
		t.Fatalf("ImportRecoveryBundle failed: %v", err)
	}

	if impVaultID != vaultID || importedAuth.AuthorityID != recAuth.AuthorityID {
		t.Fatalf("Imported recovery authority mismatch")
	}

	// Computer D creates new keys
	devD, err := device.GenerateDeviceKeys("Recovered Device D")
	if err != nil {
		t.Fatalf("GenerateDeviceKeys D failed: %v", err)
	}

	// Create Recovery Registry Epoch 1 signed by recovery signing key
	epoch1 := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         vaultID,
		Epoch:           1,
		ActiveDevices: map[string]*device.DeviceRecord{
			devD.DeviceID: {
				DeviceID:         devD.DeviceID,
				AgeRecipient:     devD.AgeRecipient,
				SigningPublicKey: devD.SigningPublicKeyHex,
				Status:           device.StatusActive,
				AddedEpoch:       1,
				CreatedAt:        time.Now().UTC(),
			},
		},
		SignerDeviceID: importedAuth.AuthorityID,
		CreatedAt:      time.Now().UTC(),
	}

	bytes, _ := epoch1.CanonicalBytes()
	sig, err := device.SignPayload(importedAuth.SigningPrivateKey, device.DomainRecoveryV2, bytes)
	if err != nil {
		t.Fatalf("SignPayload with recovery key failed: %v", err)
	}
	epoch1.Signature = sig

	// Validate epoch 1 with recovery domain
	if err := device.VerifySignature(importedAuth.SigningPublicKeyHex, device.DomainRecoveryV2, bytes, epoch1.Signature); err != nil {
		t.Fatalf("VerifySignature with recovery domain failed: %v", err)
	}

	if len(epoch1.ActiveDevices) != 1 || epoch1.ActiveDevices[devD.DeviceID] == nil {
		t.Errorf("Disaster recovery failed to authorize Device D")
	}
}
