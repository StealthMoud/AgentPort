package device

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	DomainPairingRequestV2  = "agentport/pairing-request/v2"
	DomainPairingApprovalV2 = "agentport/pairing-approval/v2"

	DefaultPairingTTL = 24 * time.Hour
)

var (
	ErrPairingExpired = errors.New("pairing request expired")
	ErrPairingInvalid = errors.New("invalid pairing request")
)

type PairingRequest struct {
	ProtocolVersion        string    `json:"protocol_version"`
	VaultID                string    `json:"vault_id"`
	RequestID              string    `json:"request_id"`
	DeviceID               string    `json:"device_id"`
	AgeRecipient           string    `json:"age_recipient"`
	SigningPublicKey       string    `json:"signing_public_key"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
	VerificationCodeDigest string    `json:"verification_code_digest"`
	Signature              string    `json:"signature"`
}

type canonicalPairingRequestPayload struct {
	ProtocolVersion        string    `json:"protocol_version"`
	VaultID                string    `json:"vault_id"`
	RequestID              string    `json:"request_id"`
	DeviceID               string    `json:"device_id"`
	AgeRecipient           string    `json:"age_recipient"`
	SigningPublicKey       string    `json:"signing_public_key"`
	CreatedAt              time.Time `json:"created_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
	VerificationCodeDigest string    `json:"verification_code_digest"`
}

// GenerateVerificationCode produces a 12-character formatted code (e.g. 8C4A-91D2-77F0) from public pairing data.
func GenerateVerificationCode(reqID, devID, recipient, signingPubKey, nonce string) string {
	combined := fmt.Sprintf("%s|%s|%s|%s|%s", reqID, devID, recipient, signingPubKey, nonce)
	sum := sha256.Sum256([]byte(combined))
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:6])) // 12 uppercase hex chars
	return fmt.Sprintf("%s-%s-%s", hexStr[0:4], hexStr[4:8], hexStr[8:12])
}

// CreatePairingRequest creates a new signed pairing request.
func CreatePairingRequest(keys *DeviceKeys, vaultID string, ttl time.Duration) (*PairingRequest, error) {
	if ttl <= 0 {
		ttl = DefaultPairingTTL
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	reqID := "req_" + hex.EncodeToString(b[:8])
	nonce := hex.EncodeToString(b[8:])

	code := GenerateVerificationCode(reqID, keys.DeviceID, keys.AgeRecipient, keys.SigningPublicKeyHex, nonce)
	codeDigest := ComputePayloadHash([]byte(code))

	now := time.Now().UTC()
	req := &PairingRequest{
		ProtocolVersion:        ProtocolVersionV2,
		VaultID:                vaultID,
		RequestID:              reqID,
		DeviceID:               keys.DeviceID,
		AgeRecipient:           keys.AgeRecipient,
		SigningPublicKey:       keys.SigningPublicKeyHex,
		CreatedAt:              now,
		ExpiresAt:              now.Add(ttl),
		Nonce:                  nonce,
		VerificationCodeDigest: codeDigest,
	}

	payload := &canonicalPairingRequestPayload{
		ProtocolVersion:        req.ProtocolVersion,
		VaultID:                req.VaultID,
		RequestID:              req.RequestID,
		DeviceID:               req.DeviceID,
		AgeRecipient:           req.AgeRecipient,
		SigningPublicKey:       req.SigningPublicKey,
		CreatedAt:              req.CreatedAt,
		ExpiresAt:              req.ExpiresAt,
		Nonce:                  req.Nonce,
		VerificationCodeDigest: req.VerificationCodeDigest,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling pairing payload: %w", err)
	}

	sig, err := SignPayload(keys.SigningPrivateKey, DomainPairingRequestV2, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed signing pairing request: %w", err)
	}
	req.Signature = sig

	return req, nil
}

// ValidatePairingRequest verifies pairing request signature, expiry, and structure.
func ValidatePairingRequest(req *PairingRequest) error {
	if req.ProtocolVersion != ProtocolVersionV2 {
		return fmt.Errorf("%w: unsupported protocol version %s", ErrPairingInvalid, req.ProtocolVersion)
	}

	if req.RequestID == "" || req.DeviceID == "" || req.AgeRecipient == "" || req.SigningPublicKey == "" {
		return fmt.Errorf("%w: missing required fields", ErrPairingInvalid)
	}

	if time.Now().UTC().After(req.ExpiresAt) {
		return ErrPairingExpired
	}

	expectedCode := GenerateVerificationCode(req.RequestID, req.DeviceID, req.AgeRecipient, req.SigningPublicKey, req.Nonce)
	if ComputePayloadHash([]byte(expectedCode)) != req.VerificationCodeDigest {
		return fmt.Errorf("%w: verification code digest mismatch", ErrPairingInvalid)
	}

	payload := &canonicalPairingRequestPayload{
		ProtocolVersion:        req.ProtocolVersion,
		VaultID:                req.VaultID,
		RequestID:              req.RequestID,
		DeviceID:               req.DeviceID,
		AgeRecipient:           req.AgeRecipient,
		SigningPublicKey:       req.SigningPublicKey,
		CreatedAt:              req.CreatedAt.UTC(),
		ExpiresAt:              req.ExpiresAt.UTC(),
		Nonce:                  req.Nonce,
		VerificationCodeDigest: req.VerificationCodeDigest,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := VerifySignature(req.SigningPublicKey, DomainPairingRequestV2, payloadBytes, req.Signature); err != nil {
		return fmt.Errorf("%w: signature verification failed: %v", ErrPairingInvalid, err)
	}

	return nil
}

type PairingApproval struct {
	RequestID             string    `json:"request_id"`
	DeviceID              string    `json:"device_id"`
	ApprovedRegistryEpoch uint64    `json:"approved_registry_epoch"`
	ApprovedRegistryHash  string    `json:"approved_registry_hash"`
	CatalogID             string    `json:"catalog_id"`
	ApproverDeviceID      string    `json:"approver_device_id"`
	CreatedAt             time.Time `json:"created_at"`
	Signature             string    `json:"signature"`
}

type canonicalApprovalPayload struct {
	RequestID             string    `json:"request_id"`
	DeviceID              string    `json:"device_id"`
	ApprovedRegistryEpoch uint64    `json:"approved_registry_epoch"`
	ApprovedRegistryHash  string    `json:"approved_registry_hash"`
	CatalogID             string    `json:"catalog_id"`
	ApproverDeviceID      string    `json:"approver_device_id"`
	CreatedAt             time.Time `json:"created_at"`
}

// CreatePairingApproval creates a signed approval receipt for a pairing request.
func CreatePairingApproval(req *PairingRequest, approverKeys *DeviceKeys, approvedEpoch uint64, approvedHash, catalogID string) (*PairingApproval, error) {
	app := &PairingApproval{
		RequestID:             req.RequestID,
		DeviceID:              req.DeviceID,
		ApprovedRegistryEpoch: approvedEpoch,
		ApprovedRegistryHash:  approvedHash,
		CatalogID:             catalogID,
		ApproverDeviceID:      approverKeys.DeviceID,
		CreatedAt:             time.Now().UTC(),
	}

	payload := &canonicalApprovalPayload{
		RequestID:             app.RequestID,
		DeviceID:              app.DeviceID,
		ApprovedRegistryEpoch: app.ApprovedRegistryEpoch,
		ApprovedRegistryHash:  app.ApprovedRegistryHash,
		CatalogID:             app.CatalogID,
		ApproverDeviceID:      app.ApproverDeviceID,
		CreatedAt:             app.CreatedAt,
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	sig, err := SignPayload(approverKeys.SigningPrivateKey, DomainPairingApprovalV2, bytes)
	if err != nil {
		return nil, err
	}
	app.Signature = sig

	return app, nil
}

// ValidatePairingApproval verifies an approval receipt signature against the approver's signing public key.
func ValidatePairingApproval(app *PairingApproval, approverPubKeyHex string) error {
	payload := &canonicalApprovalPayload{
		RequestID:             app.RequestID,
		DeviceID:              app.DeviceID,
		ApprovedRegistryEpoch: app.ApprovedRegistryEpoch,
		ApprovedRegistryHash:  app.ApprovedRegistryHash,
		CatalogID:             app.CatalogID,
		ApproverDeviceID:      app.ApproverDeviceID,
		CreatedAt:             app.CreatedAt.UTC(),
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return VerifySignature(approverPubKeyHex, DomainPairingApprovalV2, bytes, app.Signature)
}
