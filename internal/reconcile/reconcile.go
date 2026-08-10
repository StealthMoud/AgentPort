package reconcile

import (
	"fmt"
	"time"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type ReconcileResult struct {
	Created   []*model.EnvelopeV2
	Updated   []*model.EnvelopeV2
	Unchanged []*model.EnvelopeV2
}

// ReconcileV2 compares imported Schema V2 envelopes against existing vault state.
// It determines whether each envelope is a CREATE (revision 1), UPDATE (revision N+1), or NO-OP (unchanged).
func ReconcileV2(v *vault.Vault, imported []*model.EnvelopeV2) (*ReconcileResult, error) {
	res := &ReconcileResult{
		Created:   make([]*model.EnvelopeV2, 0),
		Updated:   make([]*model.EnvelopeV2, 0),
		Unchanged: make([]*model.EnvelopeV2, 0),
	}

	existingEntities := v.ListEntities()

	// Build index of existing entities by ID and by logical source key
	byID := make(map[string]*model.EnvelopeV2)
	byLogicalKey := make(map[string]*model.EnvelopeV2)

	for _, existing := range existingEntities {
		byID[existing.ID] = existing
		if existing.SourceRecord != nil && existing.SourceRecord.LogicalSourceKey != "" {
			// MachineID is intentionally excluded: logical identity must be portable across machines.
			key := fmt.Sprintf("%s|%s|%s", existing.SourceRecord.Provider, existing.ProjectID, existing.SourceRecord.LogicalSourceKey)
			byLogicalKey[key] = existing
		} else if len(existing.Provenance) > 0 {
			p := existing.Provenance[0]
			// MachineID excluded from portable key.
			key := fmt.Sprintf("%s|%s|%s|%s", p.Provider, existing.ProjectID, string(existing.Kind), p.SourcePath)
			byLogicalKey[key] = existing
		}
	}

	for _, imp := range imported {
		cloned := imp.Clone()
		if cloned.SchemaVersion == "" {
			cloned.SchemaVersion = model.SchemaVersionV2
		}

		var match *model.EnvelopeV2

		// 1. Direct ID match
		if cloned.ID != "" {
			if existing, ok := byID[cloned.ID]; ok {
				match = existing
			}
		}

		// 2. Logical source key match (MachineID excluded for portability)
		if match == nil && cloned.SourceRecord != nil && cloned.SourceRecord.LogicalSourceKey != "" {
			key := fmt.Sprintf("%s|%s|%s", cloned.SourceRecord.Provider, cloned.ProjectID, cloned.SourceRecord.LogicalSourceKey)
			if existing, ok := byLogicalKey[key]; ok {
				match = existing
			}
		}

		// 3. Provenance match (MachineID excluded for portability)
		if match == nil && len(cloned.Provenance) > 0 {
			p := cloned.Provenance[0]
			key := fmt.Sprintf("%s|%s|%s|%s", p.Provider, cloned.ProjectID, string(cloned.Kind), p.SourcePath)
			if existing, ok := byLogicalKey[key]; ok {
				match = existing
			}
		}

		if match == nil {
			// CREATE: Brand new entity
			if cloned.ID == "" {
				prefix := "apm"
				if cloned.Kind == model.KindSourceRecord {
					prefix = "apsr"
				} else if cloned.Kind == model.KindInstructionV2 {
					prefix = "api"
				} else if cloned.Kind == model.KindSkillPackage {
					prefix = "apsk"
				} else if cloned.Kind == model.KindAgentDef {
					prefix = "apag"
				} else if cloned.Kind == model.KindMCPToolDef {
					prefix = "apt"
				}
				cloned.ID = model.GenerateEntityID(prefix)
			}
			cloned.Revision = 1
			if cloned.CreatedAt.IsZero() {
				cloned.CreatedAt = time.Now()
			}
			cloned.UpdatedAt = cloned.CreatedAt
			if cloned.SourceRecord != nil {
				cloned.SourceRecord.Revision = 1
			}
			cloned.RevisionHash = model.ComputeRevisionHash(cloned)

			res.Created = append(res.Created, cloned)
			byID[cloned.ID] = cloned
		} else {
			// Compare content / hash to check if unchanged
			isUnchanged := false
			if cloned.SourceRecord != nil && match.SourceRecord != nil {
				if cloned.SourceRecord.SourceHash == match.SourceRecord.SourceHash && cloned.SourceRecord.Content == match.SourceRecord.Content {
					isUnchanged = true
				}
			} else {
				tempCloned := cloned.Clone()
				tempCloned.ID = match.ID
				tempCloned.Revision = match.Revision
				tempCloned.CreatedAt = match.CreatedAt
				tempCloned.UpdatedAt = match.UpdatedAt
				tempCloned.RevisionHash = model.ComputeRevisionHash(tempCloned)
				if tempCloned.RevisionHash == match.RevisionHash {
					isUnchanged = true
				}
			}

			if isUnchanged {
				// NO-OP: Preserve match exact state without timestamp churn
				res.Unchanged = append(res.Unchanged, match.Clone())
			} else {
				// UPDATE: Increment Revision, preserve ID, recompute RevisionHash
				updated := cloned.Clone()
				updated.ID = match.ID
				updated.Revision = match.Revision + 1
				updated.CreatedAt = match.CreatedAt
				updated.UpdatedAt = time.Now()

				if updated.SourceRecord != nil {
					updated.SourceRecord.Revision = updated.Revision
					if match.SourceRecord != nil && match.SourceRecord.SourceHash != "" {
						updated.SourceRecord.PreviousRevision = match.SourceRecord.SourceHash
					} else {
						updated.SourceRecord.PreviousRevision = match.RevisionHash
					}
				}

				updated.RevisionHash = model.ComputeRevisionHash(updated)
				res.Updated = append(res.Updated, updated)
				byID[updated.ID] = updated
			}
		}
	}

	return res, nil
}
