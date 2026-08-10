package governance

import (
	"fmt"

	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

// ApplyProposals transactionally applies a set of memory compiler proposals with strict state root checking and backup snapshot.
func ApplyProposals(v *vault.Vault, cfg *config.Config, props []*compiler.Proposal) error {
	if len(props) == 0 {
		return nil
	}

	// 1. Compute V2-aware state root
	entities := v.ListEntities()
	currentStateRoot := model.ComputeV2StateRoot(entities)
	if len(entities) == 0 {
		currentStateRoot = compiler.ComputeStateRoot(v.ListArtifacts())
	}

	// 2. Validate expected state root across all proposals in set
	for _, prop := range props {
		if prop.InputStateRoot != "" && prop.InputStateRoot != currentStateRoot {
			return fmt.Errorf("stale proposal %s rejected: proposal state root (%s) != current vault state root (%s)", prop.ID, prop.InputStateRoot, currentStateRoot)
		}
	}

	// 3. Create mandatory pre-apply backup snapshot for genuine atomic undo capability (FAIL CLOSED if snapshot fails)
	snapMgr := snapshot.NewManager(cfg)
	snap, snapErr := snapMgr.CreateSnapshot(v, "pre_governance_apply")
	if snapErr != nil {
		return fmt.Errorf("failed creating mandatory pre-governance backup snapshot: %w", snapErr)
	}
	snapID := snap.SnapshotID

	// 4. Begin atomic transaction
	tx := v.BeginTx()

	for _, prop := range props {
		switch prop.Operation {
		case compiler.OpCreate:
			env := &model.EnvelopeV2{
				ID:            model.GenerateEntityID("apm"),
				SchemaVersion: model.SchemaVersionV2,
				Kind:          model.KindMemoryV2,
				Scope:         model.ScopeGlobal,
				Revision:      1,
				Memory: &model.MemoryPayload{
					Statement:   prop.ProposedState,
					Category:    model.CategoryWorkflow,
					Status:      model.MemoryStatusActive,
					Importance:  8,
					Confidence:  prop.Confidence,
					Derivation:  model.DerivationSummarized,
					ReviewState: "approved",
				},
			}
			env.RevisionHash = model.ComputeRevisionHash(env)
			if err := tx.SaveEntity(env); err != nil {
				_ = tx.Rollback()
				return err
			}

		case compiler.OpMerge:
			mergedEnv := &model.EnvelopeV2{
				ID:            model.GenerateEntityID("apm"),
				SchemaVersion: model.SchemaVersionV2,
				Kind:          model.KindMemoryV2,
				Scope:         model.ScopeGlobal,
				Revision:      1,
				Memory: &model.MemoryPayload{
					Statement:   prop.ProposedState,
					Category:    model.CategoryWorkflow,
					Status:      model.MemoryStatusActive,
					Importance:  8,
					Confidence:  prop.Confidence,
					Derivation:  model.DerivationSummarized,
					Supersedes:  prop.TargetIDs,
					ReviewState: "approved",
				},
			}
			mergedEnv.RevisionHash = model.ComputeRevisionHash(mergedEnv)
			if err := tx.SaveEntity(mergedEnv); err != nil {
				_ = tx.Rollback()
				return err
			}

			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Status = model.MemoryStatusSuperseded
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpRefine:
			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Statement = prop.ProposedState
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpSupersede:
			newEnv := &model.EnvelopeV2{
				ID:            model.GenerateEntityID("apm"),
				SchemaVersion: model.SchemaVersionV2,
				Kind:          model.KindMemoryV2,
				Scope:         model.ScopeGlobal,
				Revision:      1,
				Memory: &model.MemoryPayload{
					Statement:   prop.ProposedState,
					Category:    model.CategoryWorkflow,
					Status:      model.MemoryStatusActive,
					Importance:  8,
					Confidence:  prop.Confidence,
					Derivation:  model.DerivationSummarized,
					Supersedes:  prop.TargetIDs,
					ReviewState: "approved",
				},
			}
			newEnv.RevisionHash = model.ComputeRevisionHash(newEnv)
			if err := tx.SaveEntity(newEnv); err != nil {
				_ = tx.Rollback()
				return err
			}

			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Status = model.MemoryStatusSuperseded
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpArchive:
			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Status = model.MemoryStatusArchived
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpMarkConflict:
			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Status = model.MemoryStatusContested
					existing.Memory.ConflictsWith = append(existing.Memory.ConflictsWith, prop.TargetIDs...)
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpMarkStale:
			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Status = model.MemoryStatusExpired
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}

		case compiler.OpReclassify:
			newCat := model.MemoryCategory(prop.ProposedState)
			for _, tid := range prop.TargetIDs {
				if existing, ok := v.GetEntity(tid); ok && existing.Memory != nil {
					existing.Memory.Category = newCat
					if err := tx.UpdateEntity(existing); err != nil {
						_ = tx.Rollback()
						return err
					}
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed committing proposal set application: %w", err)
	}

	// 5. Audit record
	j := NewJournal(cfg)
	ps := NewProposalStore(cfg)

	for _, prop := range props {
		prop.Status = compiler.ProposalStatusAccepted
		if err := ps.SaveProposal(prop); err != nil {
			return fmt.Errorf("failed saving proposal status for %s: %w", prop.ID, err)
		}
		if err := j.RecordEvent(&AuditEvent{
			Actor:      "memory_compiler",
			Operation:  string(prop.Operation),
			ProposalID: prop.ID,
			TargetID:   prop.ID,
			SnapshotID: snapID,
		}); err != nil {
			return fmt.Errorf("failed recording audit event for %s: %w", prop.ID, err)
		}
	}

	return nil
}
