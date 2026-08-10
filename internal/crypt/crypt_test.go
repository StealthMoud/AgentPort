package crypt_test

import (
	"path/filepath"
	"testing"

	"filippo.io/age"
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

func TestMultiRecipientEncryption(t *testing.T) {
	kp1, _ := crypt.GenerateKeyPair()
	kp2, _ := crypt.GenerateKeyPair()
	kp3, _ := crypt.GenerateKeyPair()

	plaintext := []byte("Multi-recipient sensitive state")

	// Encrypt to kp1 and kp2
	ciphertext, err := crypt.EncryptToRecipients([]age.Recipient{kp1.Recipient, kp2.Recipient}, plaintext)
	if err != nil {
		t.Fatalf("EncryptToRecipients failed: %v", err)
	}

	// Both kp1 and kp2 should decrypt cleanly
	d1, err := crypt.Decrypt(kp1.Identity, ciphertext)
	if err != nil || string(d1) != string(plaintext) {
		t.Errorf("kp1 decryption failed: %v, got %q", err, string(d1))
	}

	d2, err := crypt.Decrypt(kp2.Identity, ciphertext)
	if err != nil || string(d2) != string(plaintext) {
		t.Errorf("kp2 decryption failed: %v, got %q", err, string(d2))
	}

	// kp3 should fail to decrypt
	_, err = crypt.Decrypt(kp3.Identity, ciphertext)
	if err == nil {
		t.Errorf("expected kp3 decryption to fail, but succeeded")
	}
}

func TestEncryptToRecipientsValidations(t *testing.T) {
	kp, _ := crypt.GenerateKeyPair()

	// Zero recipients
	_, err := crypt.EncryptToRecipients(nil, []byte("data"))
	if err == nil {
		t.Errorf("expected error for nil recipients slice")
	}

	_, err = crypt.EncryptToRecipients([]age.Recipient{}, []byte("data"))
	if err == nil {
		t.Errorf("expected error for empty recipients slice")
	}

	// Nil recipient in slice
	_, err = crypt.EncryptToRecipients([]age.Recipient{kp.Recipient, nil}, []byte("data"))
	if err == nil {
		t.Errorf("expected error for nil element in recipients slice")
	}

	// Deduplication check
	ciphertext, err := crypt.EncryptToRecipients([]age.Recipient{kp.Recipient, kp.Recipient}, []byte("data"))
	if err != nil {
		t.Fatalf("deduplicated encryption failed: %v", err)
	}
	d, err := crypt.Decrypt(kp.Identity, ciphertext)
	if err != nil || string(d) != "data" {
		t.Errorf("decryption failed after deduplication: %v", err)
	}
}

func TestRecipientSetHash(t *testing.T) {
	h1 := crypt.RecipientSetHash([]string{"age1b", "age1a"})
	h2 := crypt.RecipientSetHash([]string{"age1a", "age1b"})

	if h1 == "" || h1 != h2 {
		t.Errorf("expected deterministic hash independent of order, got %q vs %q", h1, h2)
	}

	h3 := crypt.RecipientSetHash([]string{"age1a"})
	if h1 == h3 {
		t.Errorf("different recipient sets produced same hash")
	}
}
