package conflict

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type ConflictType string

const (
	TypeModifyModify ConflictType = "modify_modify"
	TypeDeleteModify ConflictType = "delete_modify"
	TypeCreateCreate ConflictType = "create_create"
)

type ConflictStatus string

const (
	StatusUnresolved ConflictStatus = "unresolved"
	StatusResolved   ConflictStatus = "resolved"
)

var (
	ErrConflictNotFound   = errors.New("conflict record not found")
	ErrConflictAlreadyResolved = errors.New("conflict is already resolved")
	ErrInvalidConflict    = errors.New("invalid conflict record")
)

// ConflictRecord represents an unresolved or resolved application-level conflict.
type ConflictRecord struct {
	ConflictID           string         `json:"conflict_id"`
	EntityID             string         `json:"entity_id"`
	Type                 ConflictType   `json:"type"`
	BaseRevisionID       string         `json:"base_revision_id,omitempty"`
	LocalRevisionID      string         `json:"local_revision_id,omitempty"`
	RemoteRevisionID     string         `json:"remote_revision_id,omitempty"`
	DetectedAt           time.Time      `json:"detected_at"`
	Status               ConflictStatus `json:"status"`
	ResolutionRevisionID string         `json:"resolution_revision_id,omitempty"`
}

// GenerateConflictID generates a unique conflict identifier string (e.g. cnf_...).
func GenerateConflictID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "cnf_" + hex.EncodeToString(b)
}

// Validate checks internal consistency of a ConflictRecord.
func (c *ConflictRecord) Validate() error {
	if c.ConflictID == "" {
		return fmt.Errorf("%w: missing conflict_id", ErrInvalidConflict)
	}
	if c.EntityID == "" {
		return fmt.Errorf("%w: missing entity_id", ErrInvalidConflict)
	}
	if c.Type == "" {
		return fmt.Errorf("%w: missing type", ErrInvalidConflict)
	}
	return nil
}
