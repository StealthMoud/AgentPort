package crypt_test

import (
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/crypt"
)

func TestKeyPairGenerationAndEncryptionRoundtrip(t *testing.T) {
	kp, err := crypt.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte("AgentPort Secret AI Memory Data - Standard Encryption Test")

	ciphertext, err := crypt.Encrypt(kp.Recipient, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Fatalf("ciphertext must not match plaintext")
	}

	decrypted, err := crypt.Decrypt(kp.Identity, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("expected decrypted text %q, got %q", string(plaintext), string(decrypted))
	}
}

func TestKeySaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "identity.age")

	kp, err := crypt.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if err := crypt.SaveIdentityToFile(kp.Identity, keyPath); err != nil {
		t.Fatalf("SaveIdentityToFile failed: %v", err)
	}

	loadedKp, err := crypt.LoadIdentityFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadIdentityFromFile failed: %v", err)
	}

	if loadedKp.Recipient.String() != kp.Recipient.String() {
		t.Errorf("loaded recipient mismatch: expected %s, got %s", kp.Recipient.String(), loadedKp.Recipient.String())
	}
}

func TestWrongIdentityFailsDecryption(t *testing.T) {
	kp1, _ := crypt.GenerateKeyPair()
	kp2, _ := crypt.GenerateKeyPair()

	plaintext := []byte("Confidential Agent State")
	ciphertext, err := crypt.Encrypt(kp1.Recipient, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = crypt.Decrypt(kp2.Identity, ciphertext)
	if err == nil {
		t.Fatalf("expected decryption failure with wrong identity, got nil")
	}
}
