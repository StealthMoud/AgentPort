package model

import (
	"fmt"
)

type MigrationPlan struct {
	V1ArtifactsCount int           `json:"v1_artifacts_count"`
	ConvertedV2      []*EnvelopeV2 `json:"converted_v2"`
}

// MigrateV1ToV2 converts a slice of V1 Artifacts into Schema V2 Envelopes deterministically.
func MigrateV1ToV2(v1Arts []*Artifact) (*MigrationPlan, error) {
	plan := &MigrationPlan{
		V1ArtifactsCount: len(v1Arts),
		ConvertedV2:      make([]*EnvelopeV2, 0, len(v1Arts)),
	}

	for _, art := range v1Arts {
		if err := art.Validate(); err != nil {
			return nil, fmt.Errorf("invalid v1 artifact %s: %w", art.ID, err)
		}

		v2ID := fmt.Sprintf("apv2_%s", art.Fingerprint[:16])

		env := &EnvelopeV2{
			ID:            v2ID,
			SchemaVersion: SchemaVersionV2,
			Kind:          EntityKind(art.Kind),
			Scope:         art.Scope,
			Revision:      1,
			RevisionHash:  art.Fingerprint,
			CreatedAt:     art.CreatedAt,
			UpdatedAt:     art.UpdatedAt,
			Lifecycle:     art.Lifecycle,
			Sensitivity:   art.Sensitivity,
			Tags:          art.Tags,
			Provenance:    art.Provenance,
			Metadata:      art.Metadata,
		}

		switch art.Kind {
		case KindMemory, KindPreference:
			env.Memory = &MemoryPayload{
				Statement:       art.Content,
				Category:        CategoryPreference,
				Status:          MemoryStatusActive,
				Importance:      5,
				Confidence:      1.0,
				Derivation:      DerivationImported,
				LastConfirmedAt: art.UpdatedAt,
				ReviewState:     "approved",
			}
			if art.Kind == KindMemory {
				env.Memory.Category = CategoryUncategorized
			}
		case KindInstruction, KindProjectContext:
			env.SourceRecord = &SourceRecord{
				ID:          fmt.Sprintf("aps_%s", art.Fingerprint[:16]),
				ContentType: art.ContentType,
				Content:     art.Content,
				Files:       art.Files,
				SourceHash:  art.Fingerprint,
				ObservedAt:  art.UpdatedAt,
				Revision:    1,
				Status:      "present",
			}
		}

		if err := env.Validate(); err != nil {
			return nil, fmt.Errorf("migrated envelope validation failed for %s: %w", art.ID, err)
		}

		plan.ConvertedV2 = append(plan.ConvertedV2, env)
	}

	return plan, nil
}
