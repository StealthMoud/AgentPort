package revision

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

// Store provides persistence and fast lookup for revision records.
type Store struct {
	mu       sync.RWMutex
	baseDir  string
	records  map[string]*RevisionRecord // Keyed by RevisionID
	byEntity map[string][]*RevisionRecord
}

// NewStore initializes a revision store at baseDir (e.g. vault/revisions).
func NewStore(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating revision store dir: %w", err)
	}

	s := &Store{
		baseDir:  baseDir,
		records:  make(map[string]*RevisionRecord),
		byEntity: make(map[string][]*RevisionRecord),
	}

	if err := s.loadAll(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) loadAll() error {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil // Directory empty or new
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(s.baseDir, entry.Name())
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		rev := &RevisionRecord{}
		if err := json.Unmarshal(bytes, rev); err == nil && rev.RevisionID != "" {
			s.records[rev.RevisionID] = rev
			s.byEntity[rev.EntityID] = append(s.byEntity[rev.EntityID], rev)
		}
	}

	// Sort byEntity slices by RevisionNumber ascending
	for entID, slice := range s.byEntity {
		sort.Slice(slice, func(i, j int) bool {
			return slice[i].RevisionNumber < slice[j].RevisionNumber
		})
		s.byEntity[entID] = slice
	}

	return nil
}

// SaveRevision saves a revision record atomically to disk if not already existing.
func (s *Store) SaveRevision(rev *RevisionRecord) error {
	if err := rev.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[rev.RevisionID]; exists {
		return nil // Immutable: already saved
	}

	bytes, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling revision %s: %w", rev.RevisionID, err)
	}

	filePath := filepath.Join(s.baseDir, rev.RevisionID+".json")
	if err := fsutil.WriteFileAtomic(filePath, bytes, 0600); err != nil {
		return fmt.Errorf("failed saving revision record %s: %w", rev.RevisionID, err)
	}

	s.records[rev.RevisionID] = rev
	s.byEntity[rev.EntityID] = append(s.byEntity[rev.EntityID], rev)

	sort.Slice(s.byEntity[rev.EntityID], func(i, j int) bool {
		return s.byEntity[rev.EntityID][i].RevisionNumber < s.byEntity[rev.EntityID][j].RevisionNumber
	})

	return nil
}

// GetRevision returns a revision by RevisionID.
func (s *Store) GetRevision(revisionID string) (*RevisionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rev, ok := s.records[revisionID]
	return rev, ok
}

// ListRevisionsForEntity returns all stored revisions for entityID ordered by RevisionNumber ascending.
func (s *Store) ListRevisionsForEntity(entityID string) []*RevisionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slice := s.byEntity[entityID]
	res := make([]*RevisionRecord, len(slice))
	copy(res, slice)
	return res
}

// GetEntityHeadRevision returns the latest revision record for entityID.
func (s *Store) GetEntityHeadRevision(entityID string) (*RevisionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slice := s.byEntity[entityID]
	if len(slice) == 0 {
		return nil, false
	}
	return slice[len(slice)-1], true
}

// GetAllRecords returns a map copy of all revision records in the store.
func (s *Store) GetAllRecords() map[string]*RevisionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make(map[string]*RevisionRecord, len(s.records))
	for k, v := range s.records {
		res[k] = v
	}
	return res
}
