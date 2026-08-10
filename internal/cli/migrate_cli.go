package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/governance"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate local vault canonical state from Schema V1 to Schema V2",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Inspect schema version status of current local vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			artifacts := v.ListArtifacts()
			v1Count := 0
			for _, art := range artifacts {
				if art.SchemaVersion == model.SchemaVersionV1 || art.SchemaVersion == "" {
					v1Count++
				}
			}

			fmt.Println("AgentPort Schema Migration Status")
			fmt.Println()
			fmt.Printf("Current Vault Schema: %s\n", v.Metadata.SchemaVersion)
			fmt.Printf("Total Artifacts:      %d\n", len(artifacts))
			fmt.Printf("V1 Legacy Artifacts:  %d\n", v1Count)
			if v1Count > 0 {
				fmt.Println("\nMigration Required: Run 'agentport migrate plan' to preview or 'agentport migrate apply' to convert.")
			} else {
				fmt.Println("\nVault is fully up to date with Schema V2.")
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "plan",
		Short: "Preview dry-run V1 to V2 schema migration plan",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			artifacts := v.ListArtifacts()
			plan, err := model.MigrateV1ToV2(artifacts)
			if err != nil {
				return fmt.Errorf("migration plan generation failed: %w", err)
			}

			fmt.Println("AgentPort Migration Plan (V1 -> V2)")
			fmt.Println()
			fmt.Printf("Artifacts to Migrate: %d\n", plan.V1ArtifactsCount)
			fmt.Printf("Proposed V2 Envelopes: %d\n\n", len(plan.ConvertedV2))

			for _, env := range plan.ConvertedV2 {
				stmt := ""
				if env.Memory != nil {
					stmt = env.Memory.Statement
				} else if env.SourceRecord != nil {
					stmt = env.SourceRecord.ContentType
				}
				fmt.Printf("  ✓ ID: %s | Kind: %s | Scope: %s\n    Statement: %s\n\n", env.ID, env.Kind, env.Scope, stmt)
			}

			fmt.Println("(Dry-run plan mode: zero files modified)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "apply",
		Short: "Transactionally apply V1 to V2 schema migration with backup snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			// 1. Create backup snapshot before migration
			snapMgr := snapshot.NewManager(cfg)
			snap, err := snapMgr.CreateSnapshot(v, "pre_v2_migration")
			if err != nil {
				return fmt.Errorf("failed creating pre-migration snapshot: %w", err)
			}
			fmt.Printf("Created backup snapshot: %s\n", snap.SnapshotID)

			// 2. Build migration plan
			artifacts := v.ListArtifacts()
			plan, err := model.MigrateV1ToV2(artifacts)
			if err != nil {
				return fmt.Errorf("migration plan failed: %w", err)
			}

			// 3. Staged transaction: Save all V2 envelopes AND delete V1 artifacts
			tx := v.BeginTx()
			for _, art := range artifacts {
				_ = tx.DeleteArtifact(art.ID)
			}
			for _, env := range plan.ConvertedV2 {
				if err := tx.SaveEntity(env); err != nil {
					_ = tx.Rollback()
					_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
					return fmt.Errorf("migration envelope staging failed: %w", err)
				}
			}

			if err := tx.Commit(); err != nil {
				_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
				return fmt.Errorf("failed migration transaction commit: %w", err)
			}

			// 4. Reopen verification pass: verify reopened vault contains all V2 entities
			reopenedVault, err := vault.LoadOpen(cfg)
			if err != nil || len(reopenedVault.ListEntities()) < len(plan.ConvertedV2) {
				_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
				return fmt.Errorf("migration reopen verification failed: expected %d V2 entities, got %d", len(plan.ConvertedV2), len(reopenedVault.ListEntities()))
			}

			// 5. Update vault schema version metadata
			v.Metadata.SchemaVersion = model.SchemaVersionV2
			metaBytes, _ := json.MarshalIndent(v.Metadata, "", "  ")
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.VaultDir, "vault.json"), metaBytes, 0600)

			// 6. Audit log event
			j := governance.NewJournal(cfg)
			_ = j.RecordEvent(&governance.AuditEvent{
				Actor:     "migration",
				Operation: "V1_TO_V2_MIGRATION",
				TargetID:  v.Metadata.VaultID,
			})

			fmt.Println("\n✓ Migration to Schema V2 successfully applied!")
			fmt.Printf("Converted %d V1 artifacts into V2 canonical state.\n", len(plan.ConvertedV2))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rollback",
		Short: "Rollback local vault canonical state from Schema V2 to Schema V1",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			// 1. Create backup snapshot
			snapMgr := snapshot.NewManager(cfg)
			snap, err := snapMgr.CreateSnapshot(v, "pre_rollback_backup")
			if err != nil {
				return fmt.Errorf("failed creating pre-rollback snapshot: %w", err)
			}

			// 2. Convert V2 entities to V1 artifacts
			entities := v.ListEntities()
			v1Artifacts := make([]*model.Artifact, 0)
			for _, env := range entities {
				if env.Kind == model.KindSourceRecord {
					continue
				}
				content := ""
				kind := model.KindInstruction
				title := env.ID
				if env.Memory != nil {
					content = env.Memory.Statement
					kind = model.KindMemory
				} else if env.Skill != nil {
					content = env.Skill.SkillMD
					title = env.Skill.Name
					kind = model.KindSkill
				} else if env.Agent != nil {
					content = env.Agent.Instructions
					title = env.Agent.Name
					kind = model.KindAgent
				} else if env.MCPTool != nil {
					content = env.MCPTool.Command
					title = env.MCPTool.Name
					kind = model.KindToolDefinition
				}
				art := &model.Artifact{
					SchemaVersion: model.SchemaVersionV1,
					Kind:          kind,
					Scope:         env.Scope,
					Title:         title,
					Content:       content,
					ContentType:   "text/markdown",
					Lifecycle:     model.LifecyclePersistent,
					Sensitivity:   env.Sensitivity,
					CreatedAt:     env.CreatedAt,
					UpdatedAt:     env.UpdatedAt,
				}
				art.UpdateFingerprint()
				art.ID = model.GenerateArtifactID(art.Kind, art.Fingerprint)
				v1Artifacts = append(v1Artifacts, art)
			}

			// 3. Perform atomic transaction swap
			tx := v.BeginTx()
			for _, env := range entities {
				_ = tx.DeleteEntity(env.ID)
			}
			for _, art := range v1Artifacts {
				if err := tx.SaveArtifact(art); err != nil {
					_ = tx.Rollback()
					_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
					return fmt.Errorf("failed saving V1 artifact during rollback: %w", err)
				}
			}

			if err := tx.Commit(); err != nil {
				_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
				return fmt.Errorf("rollback transaction failed: %w", err)
			}

			// 4. Update vault metadata
			v.Metadata.SchemaVersion = model.SchemaVersionV1
			metaBytes, _ := json.MarshalIndent(v.Metadata, "", "  ")
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.VaultDir, "vault.json"), metaBytes, 0600)

			// 5. Audit event
			j := governance.NewJournal(cfg)
			_ = j.RecordEvent(&governance.AuditEvent{
				Actor:     "migration",
				Operation: "V2_TO_V1_ROLLBACK",
				TargetID:  v.Metadata.VaultID,
			})

			fmt.Println("\n✓ Rollback to Schema V1 successfully applied!")
			fmt.Printf("Converted %d V2 entities back to V1 artifacts.\n", len(v1Artifacts))
			return nil
		},
	})

	return cmd
}
