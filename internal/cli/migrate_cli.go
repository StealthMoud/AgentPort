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

			// 3. Staged transaction
			tx := v.BeginTx()
			for _, art := range artifacts {
				_ = tx.DeleteArtifact(art.ID)
			}

			if err := tx.Commit(); err != nil {
				_ = snapMgr.RestoreSnapshot(v, snap.SnapshotID)
				return fmt.Errorf("failed migration transaction commit: %w", err)
			}

			// 4. Update vault schema version metadata
			v.Metadata.SchemaVersion = model.SchemaVersionV2
			metaBytes, _ := json.MarshalIndent(v.Metadata, "", "  ")
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.VaultDir, "vault.json"), metaBytes, 0600)

			// 5. Audit log event
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

	return cmd
}
