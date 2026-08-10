package device_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/device"
)

func TestDeviceKeysGenerationAndStorage(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		HomeDir:      tempDir,
		KeysDir:      filepath.Join(tempDir, "keys"),
		VaultDir:     filepath.Join(tempDir, "vault"),
		SyncRepoDir:  filepath.Join(tempDir, "sync"),
		SnapshotsDir: filepath.Join(tempDir, "snapshots"),
	}

	keys, err := device.GenerateDeviceKeys("Test MacBook Air")
	if err != nil {
		t.Fatalf("GenerateDeviceKeys failed: %v", err)
	}

	if keys.DeviceID == "" || keys.AgeRecipient == "" || keys.SigningPublicKeyHex == "" {
		t.Fatalf("GenerateDeviceKeys produced incomplete keys: %+v", keys)
	}

	if err := device.SaveDeviceKeys(cfg, keys); err != nil {
		t.Fatalf("SaveDeviceKeys failed: %v", err)
	}

	loaded, err := device.LoadDeviceKeys(cfg)
	if err != nil {
		t.Fatalf("LoadDeviceKeys failed: %v", err)
	}

	if loaded.DeviceID != keys.DeviceID {
		t.Errorf("DeviceID mismatch: got %s, want %s", loaded.DeviceID, keys.DeviceID)
	}

	if loaded.AgeRecipient != keys.AgeRecipient {
		t.Errorf("AgeRecipient mismatch: got %s, want %s", loaded.AgeRecipient, keys.AgeRecipient)
	}

	if loaded.SigningPublicKeyHex != keys.SigningPublicKeyHex {
		t.Errorf("SigningPublicKey mismatch: got %s, want %s", loaded.SigningPublicKeyHex, keys.SigningPublicKeyHex)
	}
}

func TestSignatureVerificationWithDomainSeparation(t *testing.T) {
	keys, _ := device.GenerateDeviceKeys("Tester")
	payload := []byte("Sensitive payload data")

	sig, err := device.SignPayload(keys.SigningPrivateKey, device.DomainRegistryV2, payload)
	if err != nil {
		t.Fatalf("SignPayload failed: %v", err)
	}

	// Correct domain verifies
	if err := device.VerifySignature(keys.SigningPublicKeyHex, device.DomainRegistryV2, payload, sig); err != nil {
		t.Errorf("VerifySignature failed with correct domain: %v", err)
	}

	// Mismatched domain fails
	if err := device.VerifySignature(keys.SigningPublicKeyHex, device.DomainPairingRequestV2, payload, sig); err == nil {
		t.Errorf("expected signature verification failure for wrong domain, but passed")
	}

	// Tampered payload fails
	if err := device.VerifySignature(keys.SigningPublicKeyHex, device.DomainRegistryV2, []byte("Tampered data"), sig); err == nil {
		t.Errorf("expected signature verification failure for tampered payload, but passed")
	}
}

func TestRegistryChainValidation(t *testing.T) {
	devA, _ := device.GenerateDeviceKeys("Device A")
	devB, _ := device.GenerateDeviceKeys("Device B")

	// Epoch 1 (Genesis)
	epoch1 := &device.RegistryEpoch{
		ProtocolVersion: device.ProtocolVersionV2,
		VaultID:         "vlt_test123",
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

	if err := device.SignRegistry(epoch1, devA); err != nil {
		t.Fatalf("SignRegistry epoch 1 failed: %v", err)
	}

	if err := device.ValidateRegistryEpoch(epoch1, nil); err != nil {
		t.Fatalf("ValidateRegistryEpoch genesis failed: %v", err)
	}

	hash1, _ := device.ComputeRegistryHash(epoch1)

	// Epoch 2 (Add Device B)
	epoch2 := &device.RegistryEpoch{
		ProtocolVersion:      device.ProtocolVersionV2,
		VaultID:              "vlt_test123",
		Epoch:                2,
		PreviousRegistryHash: hash1,
		ActiveDevices: map[string]*device.DeviceRecord{
			devA.DeviceID: epoch1.ActiveDevices[devA.DeviceID],
			devB.DeviceID: {
				DeviceID:         devB.DeviceID,
				AgeRecipient:     devB.AgeRecipient,
				SigningPublicKey: devB.SigningPublicKeyHex,
				Status:           device.StatusActive,
				AddedEpoch:       2,
				CreatedAt:        time.Now().UTC(),
			},
		},
		SignerDeviceID: devA.DeviceID,
		CreatedAt:      time.Now().UTC(),
	}

	if err := device.SignRegistry(epoch2, devA); err != nil {
		t.Fatalf("SignRegistry epoch 2 failed: %v", err)
	}

	if err := device.ValidateRegistryChain([]*device.RegistryEpoch{epoch1, epoch2}); err != nil {
		t.Fatalf("ValidateRegistryChain failed: %v", err)
	}

	// Test Rollback / Tampered Epoch
	epoch2Tampered := *epoch2
	epoch2Tampered.PreviousRegistryHash = "badhash"
	if err := device.ValidateRegistryEpoch(&epoch2Tampered, epoch1); err == nil {
		t.Errorf("expected validation failure for tampered previous_registry_hash")
	}
}

func TestPairingFlow(t *testing.T) {
	devA, _ := device.GenerateDeviceKeys("Device A") // Existing authorized device
	devB, _ := device.GenerateDeviceKeys("Device B") // Requesting new device

	req, err := device.CreatePairingRequest(devB, "vlt_test123", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreatePairingRequest failed: %v", err)
	}

	if err := device.ValidatePairingRequest(req); err != nil {
		t.Fatalf("ValidatePairingRequest failed: %v", err)
	}

	// Verification code check
	code := device.GenerateVerificationCode(req.RequestID, req.DeviceID, req.AgeRecipient, req.SigningPublicKey, req.Nonce)
	if len(code) != 14 || code[4] != '-' || code[9] != '-' {
		t.Errorf("unexpected verification code format: %s", code)
	}

	// Approval creation by devA
	approval, err := device.CreatePairingApproval(req, devA, 2, "hash123", "cat123")
	if err != nil {
		t.Fatalf("CreatePairingApproval failed: %v", err)
	}

	if err := device.ValidatePairingApproval(approval, devA.SigningPublicKeyHex); err != nil {
		t.Fatalf("ValidatePairingApproval failed: %v", err)
	}
}

func TestRecoveryAuthorityExportAndImport(t *testing.T) {
	tempDir := t.TempDir()
	bundlePath := filepath.Join(tempDir, "recovery_bundle.age")

	recAuth, err := device.GenerateRecoveryAuthority()
	if err != nil {
		t.Fatalf("GenerateRecoveryAuthority failed: %v", err)
	}

	passphrase := "super-secret-recovery-passphrase-123!"

	if err := device.ExportRecoveryBundle(recAuth, "vlt_test123", bundlePath, passphrase); err != nil {
		t.Fatalf("ExportRecoveryBundle failed: %v", err)
	}

	imported, vaultID, err := device.ImportRecoveryBundle(bundlePath, passphrase, nil)
	if err != nil {
		t.Fatalf("ImportRecoveryBundle failed: %v", err)
	}

	if vaultID != "vlt_test123" {
		t.Errorf("vaultID mismatch: got %s, want vlt_test123", vaultID)
	}

	if imported.AuthorityID != recAuth.AuthorityID {
		t.Errorf("AuthorityID mismatch: got %s, want %s", imported.AuthorityID, recAuth.AuthorityID)
	}

	if imported.AgeRecipient != recAuth.AgeRecipient {
		t.Errorf("AgeRecipient mismatch: got %s, want %s", imported.AgeRecipient, recAuth.AgeRecipient)
	}

	// Wrong passphrase fails
	_, _, err = device.ImportRecoveryBundle(bundlePath, "wrong-passphrase", nil)
	if err == nil {
		t.Errorf("expected failure when importing with wrong passphrase")
	}
}

func TestLocalTrustAnchorRollbackProtection(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{HomeDir: tempDir}

	trust := &device.LocalTrustAnchor{
		VaultID:              "vlt_test123",
		HighestRegistryEpoch: 5,
		RegistryHeadHash:     "hash5",
	}

	if err := device.SaveTrustAnchor(cfg, trust); err != nil {
		t.Fatalf("SaveTrustAnchor failed: %v", err)
	}

	loaded, err := device.LoadTrustAnchor(cfg)
	if err != nil {
		t.Fatalf("LoadTrustAnchor failed: %v", err)
	}

	if loaded.HighestRegistryEpoch != 5 {
		t.Errorf("HighestRegistryEpoch mismatch: got %d, want 5", loaded.HighestRegistryEpoch)
	}

	// Verification against epoch 4 fails (rollback)
	epoch4 := &device.RegistryEpoch{
		VaultID: "vlt_test123",
		Epoch:   4,
	}

	if err := device.VerifyAgainstTrustAnchor(loaded, epoch4); err == nil {
		t.Errorf("expected ErrRegistryRollback when validating epoch 4 against trust anchor epoch 5")
	}
}
