package revision_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/revision"
)

func TestRevisionStoreAndAncestry(t *testing.T) {
	tempDir := t.TempDir()
	store, err := revision.NewStore(filepath.Join(tempDir, "revisions"))
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	rev1 := &revision.RevisionRecord{
		RevisionID:           "rev_1",
		EntityID:             "apm_test1",
		RevisionNumber:       1,
		SemanticRevisionHash: "hash_v1",
		AuthorDeviceID:       "dev_a",
		CreatedAt:            time.Now().UTC(),
	}

	rev2 := &revision.RevisionRecord{
		RevisionID:           "rev_2",
		EntityID:             "apm_test1",
		RevisionNumber:       2,
		SemanticRevisionHash: "hash_v2",
		ParentRevisionIDs:    []string{"rev_1"},
		AuthorDeviceID:       "dev_a",
		CreatedAt:            time.Now().UTC(),
	}

	rev3a := &revision.RevisionRecord{
		RevisionID:           "rev_3a",
		EntityID:             "apm_test1",
		RevisionNumber:       3,
		SemanticRevisionHash: "hash_v3a",
		ParentRevisionIDs:    []string{"rev_2"},
		AuthorDeviceID:       "dev_a",
		CreatedAt:            time.Now().UTC(),
	}

	rev3b := &revision.RevisionRecord{
		RevisionID:           "rev_3b",
		EntityID:             "apm_test1",
		RevisionNumber:       3,
		SemanticRevisionHash: "hash_v3b",
		ParentRevisionIDs:    []string{"rev_2"},
		AuthorDeviceID:       "dev_b",
		CreatedAt:            time.Now().UTC(),
	}

	// Save all revisions
	for _, r := range []*revision.RevisionRecord{rev1, rev2, rev3a, rev3b} {
		if err := store.SaveRevision(r); err != nil {
			t.Fatalf("SaveRevision failed for %s: %v", r.RevisionID, err)
		}
	}

	// Verify Store retrievals
	rFetch, ok := store.GetRevision("rev_2")
	if !ok || rFetch.SemanticRevisionHash != "hash_v2" {
		t.Errorf("GetRevision failed for rev_2")
	}

	revisions := store.ListRevisionsForEntity("apm_test1")
	if len(revisions) != 4 {
		t.Errorf("expected 4 revisions, got %d", len(revisions))
	}

	// Ancestry checks
	graph := store.GetAllRecords()

	if !revision.IsAncestor(graph, "rev_1", "rev_3a") {
		t.Errorf("expected rev_1 to be ancestor of rev_3a")
	}

	if !revision.IsAncestor(graph, "rev_2", "rev_3b") {
		t.Errorf("expected rev_2 to be ancestor of rev_3b")
	}

	if revision.IsAncestor(graph, "rev_3a", "rev_3b") {
		t.Errorf("rev_3a should NOT be ancestor of rev_3b")
	}

	// Lowest Common Ancestor check between divergent rev3a and rev3b
	lca, found := revision.FindLowestCommonAncestor(graph, "rev_3a", "rev_3b")
	if !found || lca.RevisionID != "rev_2" {
		t.Errorf("expected LCA of rev_3a and rev_3b to be rev_2, got %v (found=%v)", lca, found)
	}
}
