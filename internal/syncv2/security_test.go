package syncv2_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/revision"
	"github.com/StealthMoud/AgentPort/internal/syncv2"
)

func TestAdversarialRegistryAttacks(t *testing.T) {
	devA, _ := device.GenerateDeviceKeys("Device A")
	devEvil, _ := device.GenerateDeviceKeys("Evil Attacker")

	epoch1 := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         "vlt_sec123",
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

	// 1. Forged device addition by attacker without signature
	epoch2Forged := *epoch1
	epoch2Forged.Epoch = 2
	epoch2Forged.ActiveDevices[devEvil.DeviceID] = &device.DeviceRecord{
		DeviceID:         devEvil.DeviceID,
		AgeRecipient:     devEvil.AgeRecipient,
		SigningPublicKey: devEvil.SigningPublicKeyHex,
		Status:           device.StatusActive,
		AddedEpoch:       2,
	}

	if err := device.ValidateRegistryEpoch(&epoch2Forged, epoch1); err == nil {
		t.Errorf("expected validation failure for forged device addition without valid signer/signature")
	}

	// 2. Duplicate DeviceID attack
	epochDup := *epoch1
	epochDup.ActiveDevices["dev_dup"] = &device.DeviceRecord{
		DeviceID:         devA.DeviceID, // Duplicate ID
		AgeRecipient:     "age1dup...",
		SigningPublicKey: "pubdup...",
		Status:           device.StatusActive,
	}
	if err := device.ValidateRegistryEpoch(&epochDup, nil); err == nil {
		t.Errorf("expected validation failure for duplicate DeviceID")
	}
}

func TestAdversarialCatalogAttacks(t *testing.T) {
	devA, registry := setupTestDeviceRegistry(t)
	devRevoked, _ := device.GenerateDeviceKeys("Revoked Device")

	// Catalog signed by unknown/unauthorized device
	cat := &syncv2.Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          registry.VaultID,
		CatalogID:        syncv2.GenerateCatalogID(),
		RegistryEpoch:    registry.Epoch,
		RegistryHash:     mustRegistryHash(registry),
		RecipientSetHash: "recip_hash",
		CreatedAt:        time.Now().UTC(),
		WriterDeviceID:   devRevoked.DeviceID,
		EntityHeads:      map[string]string{"apm_1": "rev_1"},
		RevisionGraph: map[string]*revision.RevisionRecord{
			"rev_1": {
				RevisionID:           "rev_1",
				EntityID:             "apm_1",
				RevisionNumber:       1,
				SemanticRevisionHash: "hash_1",
				AuthorDeviceID:       devRevoked.DeviceID,
				CreatedAt:            time.Now().UTC(),
			},
		},
		ObjectRefs: make(map[string]*syncv2.ObjectRefInfo),
	}

	_ = syncv2.SignCatalog(cat, devRevoked)

	// ValidateCatalog should fail because devRevoked is NOT active in registry
	if err := syncv2.ValidateCatalog(cat, registry); err == nil {
		t.Errorf("expected ValidateCatalog to reject catalog signed by unauthorized/revoked device")
	}

	// Catalog with tampered ciphertext payload
	recipient, _ := device.GetRecipientFromRecipientString(devA.AgeRecipient)
	ciphertext, _ := syncv2.EncryptCatalog(cat, []age.Recipient{recipient})
	ciphertext[len(ciphertext)/2] ^= 0xFF // Flip bits in ciphertext

	_, err := syncv2.DecryptCatalog(ciphertext, devA.AgeIdentity)
	if err == nil {
		t.Errorf("expected decryption error for tampered catalog ciphertext")
	}
}

func TestRevokedDeviceCannotDecryptFutureState(t *testing.T) {
	devA, _ := device.GenerateDeviceKeys("Device A")
	devB, _ := device.GenerateDeviceKeys("Device B (Revoked)")

	plaintext1 := []byte("Initial shared secret state")

	recipA, _ := device.GetRecipientFromRecipientString(devA.AgeRecipient)
	recipB, _ := device.GetRecipientFromRecipientString(devB.AgeRecipient)

	// Initial encryption to both A and B
	cipher1, err := crypt.EncryptToRecipients([]age.Recipient{recipA, recipB}, plaintext1)
	if err != nil {
		t.Fatalf("EncryptToRecipients failed: %v", err)
	}

	// Both A and B decrypt cipher1
	if _, err := crypt.Decrypt(devA.AgeIdentity, cipher1); err != nil {
		t.Fatalf("devA failed decrypting cipher1: %v", err)
	}
	if _, err := crypt.Decrypt(devB.AgeIdentity, cipher1); err != nil {
		t.Fatalf("devB failed decrypting cipher1: %v", err)
	}

	// Revoke B: Future state encrypted ONLY for A
	plaintext2 := []byte("Post-revocation secret state")
	cipher2, err := crypt.EncryptToRecipients([]age.Recipient{recipA}, plaintext2)
	if err != nil {
		t.Fatalf("EncryptToRecipients failed: %v", err)
	}

	// devA decrypts cipher2 cleanly
	dec2A, err := crypt.Decrypt(devA.AgeIdentity, cipher2)
	if err != nil || string(dec2A) != string(plaintext2) {
		t.Errorf("devA failed decrypting cipher2: %v", err)
	}

	// devB MUST FAIL to decrypt cipher2
	_, err = crypt.Decrypt(devB.AgeIdentity, cipher2)
	if err == nil {
		t.Errorf("CRITICAL SECURITY VIOLATION: revoked device B decrypted post-revocation ciphertext!")
	}
}

func TestRemotePlaintextAudit(t *testing.T) {
	tempDir := t.TempDir()

	// Write mock V2 transport repo files
	protoMeta := &syncv2.ProtocolMetadata{
		ProtocolVersion:  "2.0",
		VaultID:          "vlt_audit123",
		RegistryEpoch:    1,
		RegistryHeadHash: "hash123",
	}
	_ = syncv2.WriteProtocolMetadata(tempDir, protoMeta)

	// Read all files in transport directory
	forbiddenTerms := []string{
		"memory", "instruction", "preference", "user_prompt",
		"AGE-SECRET-KEY", "PRIVATE KEY", "/Users/", "/home/", "C:\\",
	}

	err := filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		str := string(bytes)
		for _, term := range forbiddenTerms {
			if stringContains(str, term) {
				t.Errorf("Remote plaintext security violation in %s: found secret or canonical term %s", path, term)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("filepath.Walk failed: %v", err)
	}
}
