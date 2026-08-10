# AgentPort Revision Graph & DAG Specification

## RevisionRecord Structure
```json
{
  "revision_id": "rev_...",
  "entity_id": "apm_...",
  "revision_number": 2,
  "semantic_revision_hash": "...",
  "parent_revision_ids": ["rev_1"],
  "author_device_id": "dev_...",
  "created_at": "2026-08-10T15:00:00Z",
  "deleted": false,
  "object_ref": "<opaque-id>.age"
}
```

## Revision Invariants
- `RevisionID` is a unique opaque node identity (`rev_...`), distinct from `SemanticRevisionHash`.
- `ParentRevisionIDs` contains 1 parent ID for normal edits, and 2 parent IDs for convergence/resolution merges.
- Deletions are modeled as revision events (`Deleted: true`), allowing deletion to participate in ancestral graph resolution.
