package syncv2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/revision"
)

const DomainCatalogV2 = "agentport/catalog/v2"

var (
	ErrCatalogInvalid  = errors.New("catalog invalid")
	ErrCatalogRollback = errors.New("catalog rollback detected")
)

type ObjectRefInfo struct {
	OpaqueObjectID       string `json:"opaque_object_id"`
	CiphertextSHA256     string `json:"ciphertext_sha256"`
	SemanticRevisionHash string `json:"semantic_revision_hash"`
	RevisionID           string `json:"revision_id"`
	EntityID             string `json:"entity_id"`
	EncryptionEpoch      uint64 `json:"encryption_epoch"`
}

type Catalog struct {
	ProtocolVersion  string                              `json:"protocol_version"`
	VaultID          string                              `json:"vault_id"`
	CatalogID        string                              `json:"catalog_id"`
	ParentCatalogIDs []string                            `json:"parent_catalog_ids,omitempty"`
	RegistryEpoch    uint64                              `json:"registry_epoch"`
	RegistryHash     string                              `json:"registry_hash"`
	RecipientSetHash string                              `json:"recipient_set_hash"`
	CreatedAt        time.Time                           `json:"created_at"`
	WriterDeviceID   string                              `json:"writer_device_id"`
	StateRoot        string                              `json:"state_root"`
	EntityHeads      map[string]string                   `json:"entity_heads"`   // EntityID -> RevisionID
	RevisionGraph    map[string]*revision.RevisionRecord `json:"revision_graph"` // RevisionID -> RevisionRecord
	ObjectRefs       map[string]*ObjectRefInfo           `json:"object_refs"`    // ObjectRef -> ObjectRefInfo
	Tombstones       []string                            `json:"tombstones,omitempty"`
	Conflicts        map[string]*conflict.ConflictRecord `json:"conflicts,omitempty"`
	Signature        string                              `json:"signature,omitempty"`
}

type canonicalCatalogPayload struct {
	ProtocolVersion  string                              `json:"protocol_version"`
	VaultID          string                              `json:"vault_id"`
	CatalogID        string                              `json:"catalog_id"`
	ParentCatalogIDs []string                            `json:"parent_catalog_ids,omitempty"`
	RegistryEpoch    uint64                              `json:"registry_epoch"`
	RegistryHash     string                              `json:"registry_hash"`
	RecipientSetHash string                              `json:"recipient_set_hash"`
	CreatedAt        time.Time                           `json:"created_at"`
	WriterDeviceID   string                              `json:"writer_device_id"`
	StateRoot        string                              `json:"state_root"`
	EntityHeads      map[string]string                   `json:"entity_heads"`
	RevisionGraph    map[string]*revision.RevisionRecord `json:"revision_graph"`
	ObjectRefs       map[string]*ObjectRefInfo           `json:"object_refs"`
	Tombstones       []string                            `json:"tombstones,omitempty"`
	Conflicts        map[string]*conflict.ConflictRecord `json:"conflicts,omitempty"`
}

// GenerateCatalogID generates a unique opaque catalog ID string (e.g. cat_...).
func GenerateCatalogID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "cat_" + hex.EncodeToString(b)
}

// CanonicalBytes produces deterministic JSON bytes of the catalog excluding signature.
func (c *Catalog) CanonicalBytes() ([]byte, error) {
	payload := &canonicalCatalogPayload{
		ProtocolVersion:  c.ProtocolVersion,
		VaultID:          c.VaultID,
		CatalogID:        c.CatalogID,
		ParentCatalogIDs: c.ParentCatalogIDs,
		RegistryEpoch:    c.RegistryEpoch,
		RegistryHash:     c.RegistryHash,
		RecipientSetHash: c.RecipientSetHash,
		CreatedAt:        c.CreatedAt.UTC(),
		WriterDeviceID:   c.WriterDeviceID,
		StateRoot:        c.StateRoot,
		EntityHeads:      c.EntityHeads,
		RevisionGraph:    c.RevisionGraph,
		ObjectRefs:       c.ObjectRefs,
		Tombstones:       c.Tombstones,
		Conflicts:        c.Conflicts,
	}
	return json.Marshal(payload)
}

// SignCatalog signs the catalog using writer device keys.
func SignCatalog(cat *Catalog, writerKeys *device.DeviceKeys) error {
	cat.WriterDeviceID = writerKeys.DeviceID
	bytes, err := cat.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("failed generating canonical bytes for catalog: %w", err)
	}

	sig, err := device.SignPayload(writerKeys.SigningPrivateKey, DomainCatalogV2, bytes)
	if err != nil {
		return fmt.Errorf("failed signing catalog: %w", err)
	}
	cat.Signature = sig
	return nil
}

// VerifyCatalogSignature verifies catalog signature against writer's signing public key hex.
func VerifyCatalogSignature(cat *Catalog, writerPubKeyHex string) error {
	bytes, err := cat.CanonicalBytes()
	if err != nil {
		return err
	}
	return device.VerifySignature(writerPubKeyHex, DomainCatalogV2, bytes, cat.Signature)
}

// ValidateCatalog checks catalog invariants and writer authorization against active registry.
func ValidateCatalog(cat *Catalog, activeRegistry *device.RegistryEpoch) error {
	if cat.ProtocolVersion != "2.0" {
		return fmt.Errorf("%w: unsupported protocol version %s", ErrCatalogInvalid, cat.ProtocolVersion)
	}
	if cat.CatalogID == "" || cat.VaultID == "" {
		return fmt.Errorf("%w: missing required catalog fields", ErrCatalogInvalid)
	}

	if activeRegistry != nil {
		if cat.VaultID != activeRegistry.VaultID {
			return fmt.Errorf("%w: vault ID mismatch (catalog %s, registry %s)", ErrCatalogInvalid, cat.VaultID, activeRegistry.VaultID)
		}
		if cat.RegistryEpoch != activeRegistry.Epoch {
			return fmt.Errorf("%w: registry epoch mismatch (catalog %d, registry %d)", ErrCatalogInvalid, cat.RegistryEpoch, activeRegistry.Epoch)
		}

		writerDev, isWriterActive := activeRegistry.ActiveDevices[cat.WriterDeviceID]
		if !isWriterActive || writerDev.Status != device.StatusActive {
			return fmt.Errorf("%w: writer device %s is not active in registry epoch %d", ErrCatalogInvalid, cat.WriterDeviceID, activeRegistry.Epoch)
		}

		if err := VerifyCatalogSignature(cat, writerDev.SigningPublicKey); err != nil {
			return fmt.Errorf("%w: signature verification failed for writer %s: %v", ErrCatalogInvalid, cat.WriterDeviceID, err)
		}
	}

	return nil
}

// ComputeStateRoot calculates a deterministic hash of all active entity heads and revision hashes.
func ComputeStateRoot(entityHeads map[string]string, graph map[string]*revision.RevisionRecord) string {
	keys := make([]string, 0, len(entityHeads))
	for entID := range entityHeads {
		keys = append(keys, entID)
	}
	sort.Strings(keys)

	var sb []string
	for _, entID := range keys {
		revID := entityHeads[entID]
		if rev, ok := graph[revID]; ok {
			sb = append(sb, fmt.Sprintf("%s:%s:%s", entID, revID, rev.SemanticRevisionHash))
		}
	}

	sum := sha256.Sum256([]byte(fmt.Sprintf("%v", sb)))
	return hex.EncodeToString(sum[:])
}

// EncryptCatalog serializes and encrypts catalog for recipient set.
func EncryptCatalog(cat *Catalog, recipients []age.Recipient) ([]byte, error) {
	bytes, err := json.Marshal(cat)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling catalog: %w", err)
	}
	return crypt.EncryptToRecipients(recipients, bytes)
}

// DecryptCatalog decrypts ciphertext using device identity and parses Catalog.
func DecryptCatalog(ciphertext []byte, identity age.Identity) (*Catalog, error) {
	plaintext, err := crypt.Decrypt(identity, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCatalogInvalid, err)
	}

	cat := &Catalog{}
	if err := json.Unmarshal(plaintext, cat); err != nil {
		return nil, fmt.Errorf("%w: corrupt catalog JSON: %v", ErrCatalogInvalid, err)
	}
	return cat, nil
}
