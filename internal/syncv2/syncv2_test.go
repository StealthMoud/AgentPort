package syncv2_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/revision"
	"github.com/StealthMoud/AgentPort/internal/syncv2"
)

func setupTestDeviceRegistry(t *testing.T) (*device.DeviceKeys, *device.RegistryEpoch) {
	devA, err := device.GenerateDeviceKeys("Device A")
	if err != nil {
		t.Fatalf("GenerateDeviceKeys failed: %v", err)
	}

	epoch := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         "vlt_sync_test",
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

	if err := device.SignRegistry(epoch, devA); err != nil {
		t.Fatalf("SignRegistry failed: %v", err)
	}
	return devA, epoch
}

func TestProtocolMetadataNonSensitive(t *testing.T) {
	tempDir := t.TempDir()
	meta := &syncv2.ProtocolMetadata{
		ProtocolVersion: "2.0",
		VaultID:         "vlt_123",
		RegistryEpoch:   1,
	}

	if err := syncv2.WriteProtocolMetadata(tempDir, meta); err != nil {
		t.Fatalf("WriteProtocolMetadata failed: %v", err)
	}

	readMeta, err := syncv2.ReadProtocolMetadata(tempDir)
	if err != nil {
		t.Fatalf("ReadProtocolMetadata failed: %v", err)
	}

	if readMeta.VaultID != "vlt_123" || readMeta.ProtocolVersion != "2.0" {
		t.Errorf("ReadProtocolMetadata mismatch: %+v", readMeta)
	}

	// Plaintext security audit on protocol.json content
	rawBytes, _ := os.ReadFile(filepath.Join(tempDir, "protocol.json"))
	rawStr := string(rawBytes)
	forbiddenTerms := []string{"memory", "instruction", "prompt", "secret", "title", "content"}
	for _, term := range forbiddenTerms {
		if stringContains(rawStr, term) {
			t.Errorf("protocol.json exposed forbidden term %s: %s", term, rawStr)
		}
	}
}

func TestCatalogSigningAndEncryption(t *testing.T) {
	devA, registry := setupTestDeviceRegistry(t)

	cat := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        syncv2.GenerateCatalogID(),
		RegistryEpoch:    registry.Epoch,
		RegistryHash:     mustRegistryHash(registry),
		RecipientSetHash: "recip_hash_1",
		CreatedAt:        time.Now().UTC(),
		WriterDeviceID:   devA.DeviceID,
		EntityHeads:      map[string]string{"apm_1": "rev_1"},
		RevisionGraph: map[string]*revision.RevisionRecord{
			"rev_1": {
				RevisionID:           "rev_1",
				EntityID:             "apm_1",
				RevisionNumber:       1,
				SemanticRevisionHash: "sem_hash_1",
				AuthorDeviceID:       devA.DeviceID,
				CreatedAt:            time.Now().UTC(),
			},
		},
		ObjectRefs: make(map[string]*syncv2.ObjectRefInfo),
	}

	if err := syncv2.SignCatalog(cat, devA); err != nil {
		t.Fatalf("SignCatalog failed: %v", err)
	}

	if err := syncv2.ValidateCatalog(cat, registry); err != nil {
		t.Fatalf("ValidateCatalog failed: %v", err)
	}

	// Encrypt catalog to devA's recipient
	recipient, _ := device.GetRecipientFromRecipientString(devA.AgeRecipient)
	ciphertext, err := syncv2.EncryptCatalog(cat, []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("EncryptCatalog failed: %v", err)
	}

	// Decrypt with devA's identity
	decryptedCat, err := syncv2.DecryptCatalog(ciphertext, devA.AgeIdentity)
	if err != nil {
		t.Fatalf("DecryptCatalog failed: %v", err)
	}

	if decryptedCat.CatalogID != cat.CatalogID || decryptedCat.WriterDeviceID != devA.DeviceID {
		t.Errorf("Decrypted catalog mismatch: %+v", decryptedCat)
	}
}

func TestMergeEngineAncestralAndConflict(t *testing.T) {
	devA, registry := setupTestDeviceRegistry(t)
	devB, _ := device.GenerateDeviceKeys("Device B")

	// Base state: Revision 1
	rev1 := &revision.RevisionRecord{
		RevisionID:           "rev_1",
		EntityID:             "apm_target",
		RevisionNumber:       1,
		SemanticRevisionHash: "hash_v1",
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	// Local state: Revision 2 (devA edits target -> hash_v2_A)
	rev2A := &revision.RevisionRecord{
		RevisionID:           "rev_2A",
		EntityID:             "apm_target",
		RevisionNumber:       2,
		SemanticRevisionHash: "hash_v2_A",
		ParentRevisionIDs:    []string{"rev_1"},
		AuthorDeviceID:       devA.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	// Remote state: Revision 2 (devB edits target -> hash_v2_B)
	rev2B := &revision.RevisionRecord{
		RevisionID:           "rev_2B",
		EntityID:             "apm_target",
		RevisionNumber:       2,
		SemanticRevisionHash: "hash_v2_B",
		ParentRevisionIDs:    []string{"rev_1"},
		AuthorDeviceID:       devB.DeviceID,
		CreatedAt:            time.Now().UTC(),
	}

	localCat := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        "cat_local",
		RegistryEpoch:    registry.Epoch,
		EntityHeads:      map[string]string{"apm_target": "rev_2A"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_1": rev1, "rev_2A": rev2A},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	remoteCat := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        "cat_remote",
		RegistryEpoch:    registry.Epoch,
		EntityHeads:      map[string]string{"apm_target": "rev_2B"},
		RevisionGraph:    map[string]*revision.RevisionRecord{"rev_1": rev1, "rev_2B": rev2B},
		ObjectRefs:       make(map[string]*syncv2.ObjectRefInfo),
	}

	// Run application merge -> expected modify/modify conflict record!
	res, err := syncv2.MergeCatalogs(localCat, remoteCat, registry, devA)
	if err != nil {
		t.Fatalf("MergeCatalogs failed: %v", err)
	}

	if !res.HasConflicts || len(res.NewConflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(res.NewConflicts))
	}

	var foundCnf *conflict.ConflictRecord
	for _, c := range res.NewConflicts {
		foundCnf = c
	}

	if foundCnf.Type != conflict.TypeModifyModify || foundCnf.EntityID != "apm_target" {
		t.Errorf("unexpected conflict record: %+v", foundCnf)
	}
}

func mustRegistryHash(ep *device.RegistryEpoch) string {
	h, _ := device.ComputeRegistryHash(ep)
	return h
}

func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
