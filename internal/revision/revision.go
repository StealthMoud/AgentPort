package revision

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	ErrInvalidRevision = errors.New("invalid revision record")
	ErrRevisionNotFound = errors.New("revision record not found")
)

// RevisionRecord represents an immutable revision node in the entity DAG.
type RevisionRecord struct {
	RevisionID           string    `json:"revision_id"`
	EntityID             string    `json:"entity_id"`
	RevisionNumber       int       `json:"revision_number"`
	SemanticRevisionHash string    `json:"semantic_revision_hash"`
	ParentRevisionIDs    []string  `json:"parent_revision_ids,omitempty"`
	AuthorDeviceID       string    `json:"author_device_id"`
	CreatedAt            time.Time `json:"created_at"`
	Deleted              bool      `json:"deleted,omitempty"`
	ObjectRef            string    `json:"object_ref,omitempty"`
}

// GenerateRevisionID generates a unique opaque revision identifier string (e.g. rev_...).
func GenerateRevisionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "rev_" + hex.EncodeToString(b)
}

// Validate checks internal consistency of a RevisionRecord.
func (r *RevisionRecord) Validate() error {
	if r.RevisionID == "" {
		return fmt.Errorf("%w: missing revision_id", ErrInvalidRevision)
	}
	if r.EntityID == "" {
		return fmt.Errorf("%w: missing entity_id", ErrInvalidRevision)
	}
	if r.RevisionNumber < 1 {
		return fmt.Errorf("%w: revision_number must be >= 1", ErrInvalidRevision)
	}
	if r.SemanticRevisionHash == "" && !r.Deleted {
		return fmt.Errorf("%w: missing semantic_revision_hash", ErrInvalidRevision)
	}
	return nil
}

// IsAncestor returns true if potentialAncestorID is an ancestor of targetID in graph.
func IsAncestor(graph map[string]*RevisionRecord, potentialAncestorID, targetID string) bool {
	if potentialAncestorID == "" || targetID == "" {
		return false
	}
	if potentialAncestorID == targetID {
		return true
	}

	visited := make(map[string]bool)
	queue := []string{targetID}

	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		if visited[currID] {
			continue
		}
		visited[currID] = true

		currNode, exists := graph[currID]
		if !exists {
			continue
		}

		for _, pID := range currNode.ParentRevisionIDs {
			if pID == potentialAncestorID {
				return true
			}
			if !visited[pID] {
				queue = append(queue, pID)
			}
		}
	}
	return false
}

// GetAncestors returns a map of all ancestor revision IDs reachable from startID (inclusive).
func GetAncestors(graph map[string]*RevisionRecord, startID string) map[string]bool {
	ancestors := make(map[string]bool)
	if startID == "" {
		return ancestors
	}

	queue := []string{startID}
	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		if ancestors[currID] {
			continue
		}
		ancestors[currID] = true

		if node, ok := graph[currID]; ok {
			for _, pID := range node.ParentRevisionIDs {
				if !ancestors[pID] {
					queue = append(queue, pID)
				}
			}
		}
	}
	return ancestors
}

// FindLowestCommonAncestor finds the lowest common ancestor (LCA) between rev1ID and rev2ID in graph.
func FindLowestCommonAncestor(graph map[string]*RevisionRecord, rev1ID, rev2ID string) (*RevisionRecord, bool) {
	if rev1ID == rev2ID {
		node, ok := graph[rev1ID]
		return node, ok
	}

	ancestors1 := GetAncestors(graph, rev1ID)
	ancestors2 := GetAncestors(graph, rev2ID)

	common := make([]*RevisionRecord, 0)
	for id := range ancestors1 {
		if ancestors2[id] {
			if node, ok := graph[id]; ok {
				common = append(common, node)
			}
		}
	}

	if len(common) == 0 {
		return nil, false
	}

	// Sort by revision number descending, then CreatedAt descending
	sort.Slice(common, func(i, j int) bool {
		if common[i].RevisionNumber != common[j].RevisionNumber {
			return common[i].RevisionNumber > common[j].RevisionNumber
		}
		return common[i].CreatedAt.After(common[j].CreatedAt)
	})

	return common[0], true
}
