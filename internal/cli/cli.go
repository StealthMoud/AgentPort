package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/config"
	contextpkg "github.com/StealthMoud/AgentPort/internal/context"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/governance"
	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/optimizer"
	"github.com/StealthMoud/AgentPort/internal/reconcile"
	"github.com/StealthMoud/AgentPort/internal/snapshot"
	"github.com/StealthMoud/AgentPort/internal/vault"
	"github.com/StealthMoud/AgentPort/internal/version"
)

// NewRootCmd initializes and constructs the main Cobra command tree.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "agentport",
		Short: "AgentPort — Portable AI-agent state and synchronization layer",
		Long: `AgentPort is an open-source, provider-independent system for making AI-agent state 
(instructions, memories, preferences, skills, agents, project context, tool definitions) 
portable across machines, operating systems, and AI coding agents.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newDoctorCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newProvidersCmd())
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newImportCmd())
	rootCmd.AddCommand(newOptimizeCmd())
	rootCmd.AddCommand(newValidateCmd())
	rootCmd.AddCommand(newCompileCmd())
	rootCmd.AddCommand(newMemoryCmd())
	rootCmd.AddCommand(newMigrateCmd())
	rootCmd.AddCommand(newExportCmd())
	rootCmd.AddCommand(newSnapshotCmd())
	rootCmd.AddCommand(newRemoteCmd())
	rootCmd.AddCommand(newSyncCmd())
	rootCmd.AddCommand(newKeyCmd())

	return rootCmd
}

func getAdapters() map[string]adapter.Adapter {
	return map[string]adapter.Adapter{
		"codex":  codex.New(""),
		"claude": claude.New(""),
		"gemini": gemini.New(""),
	}
}

func newVersionCmd() *cobra.Command {
	var fullFlag bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print AgentPort CLI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fullFlag {
				fmt.Println(version.Full())
			} else {
				fmt.Println(version.String())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fullFlag, "full", false, "Print detailed build and environment information")
	return cmd
}

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize local AgentPort vault and encryption key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			v, err := vault.Initialize(cfg)
			if err != nil {
				return err
			}

			fmt.Println("AgentPort initialized.")
			fmt.Println()
			fmt.Printf("Vault\n")
			fmt.Printf("  ID:        %s\n", v.Metadata.VaultID)
			fmt.Printf("  Schema:    %s\n", v.Metadata.SchemaVersion)
			fmt.Printf("  Encrypted: yes\n")
			fmt.Println()
			fmt.Printf("Machine\n")
			fmt.Printf("  ID:        %s\n", v.Machine.MachineID)
			fmt.Println()
			fmt.Println("Next:")
			fmt.Println("  agentport scan")
			return nil
		},
	}
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check system readiness and environment diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			fmt.Println("AgentPort Doctor")
			fmt.Println()

			healthy := true

			// Check config dir
			if _, err := os.Stat(cfg.HomeDir); err == nil {
				fmt.Printf("✓ AgentPort configuration directory (%s)\n", cfg.HomeDir)
			} else {
				fmt.Printf("✗ Configuration directory missing (%s)\n", cfg.HomeDir)
				healthy = false
			}

			v, err := vault.LoadOpen(cfg)
			if err == nil {
				fmt.Println("✓ Vault initialized")
				if v.Key != nil && v.Key.Identity != nil {
					fmt.Println("✓ Encryption identity available")
				} else {
					fmt.Println("✗ Encryption identity missing")
					healthy = false
				}

				validation := v.Validate()
				if validation.Healthy {
					fmt.Println("✓ Vault validates cleanly")
				} else {
					fmt.Printf("✗ Vault validation errors: %v\n", validation.Errors)
					healthy = false
				}
			} else {
				fmt.Println("○ Vault not initialized (run 'agentport init')")
			}

			// Provider detection
			adapters := getAdapters()
			for name, ad := range adapters {
				det, _ := ad.Detect(ctx)
				if det.Detected {
					fmt.Printf("✓ Provider %s detected (%s)\n", name, det.RootPath)
				} else {
					fmt.Printf("○ Provider %s not installed\n", name)
				}
			}

			fmt.Println()
			if healthy {
				fmt.Println("Result: healthy")
			} else {
				fmt.Println("Result: issues detected")
			}
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display AgentPort vault and synchronization status",
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

			store := gitstore.New(cfg)
			remoteURL, _ := store.GetRemote(ctx)

			entities := v.ListEntities()
			artifacts := v.ListArtifacts()
			tombstones, _ := v.ListTombstones()
			tombstoneCount := len(tombstones)
			stateRoot := model.ComputeV2StateRoot(entities)
			if len(entities) == 0 {
				stateRoot = compiler.ComputeStateRoot(artifacts)
			}

			if jsonOutput {
				statusObj := map[string]interface{}{
					"vault_id":        v.Metadata.VaultID,
					"schema_version":  v.Metadata.SchemaVersion,
					"entity_count":    len(entities),
					"artifact_count":  len(artifacts),
					"tombstone_count": tombstoneCount,
					"state_root":      stateRoot,
					"remote_url":      remoteURL,
					"machine_id":      v.Machine.MachineID,
				}
				data, _ := json.MarshalIndent(statusObj, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("AgentPort Status")
			fmt.Println()
			fmt.Printf("Vault:        %s\n", v.Metadata.VaultID)
			fmt.Printf("Schema:       %s\n", v.Metadata.SchemaVersion)
			fmt.Printf("V2 Entities:  %d\n", len(entities))
			fmt.Printf("V1 Artifacts: %d\n", len(artifacts))
			fmt.Printf("Tombstones:   %d\n", tombstoneCount)
			fmt.Printf("State Root:   %s\n", stateRoot)
			fmt.Printf("Machine ID:   %s\n", v.Machine.MachineID)
			if remoteURL != "" {
				fmt.Printf("Git Remote:   %s\n", remoteURL)
			} else {
				fmt.Printf("Git Remote:   not configured\n")
			}
			fmt.Printf("Encryption:   enabled (Age X25519)\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output status in JSON format")
	return cmd
}

func newProvidersCmd() *cobra.Command {
	var jsonOutput bool
	var capFlag bool
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "Detect installed AI coding agent providers and their capabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			adapters := getAdapters()

			if capFlag {
				capMap := make(map[string]adapter.Capabilities)
				for name, ad := range adapters {
					capMap[name] = ad.Capabilities()
				}
				if jsonOutput {
					data, _ := json.MarshalIndent(capMap, "", "  ")
					fmt.Println(string(data))
					return nil
				}
				fmt.Println("Provider Capabilities")
				fmt.Println()
				for name, caps := range capMap {
					fmt.Printf("%s:\n", strings.Title(name))
					fmt.Printf("  Instructions: %s\n", caps.Instructions)
					fmt.Printf("  Memory:       %s\n", caps.Memory)
					fmt.Printf("  Skills:       %s\n", caps.Skills)
					fmt.Printf("  Agents:       %s\n", caps.Agents)
					fmt.Printf("  MCP:          %s\n", caps.MCP)
					fmt.Printf("  ProjectRules: %s\n\n", caps.ProjectRules)
				}
				return nil
			}

			results := make([]*adapter.DetectResult, 0)
			for _, ad := range adapters {
				det, err := ad.Detect(ctx)
				if err == nil {
					results = append(results, det)
				}
			}

			if jsonOutput {
				data, _ := json.MarshalIndent(results, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("Providers")
			fmt.Println()
			for _, res := range results {
				if res.Detected {
					fmt.Printf("✓ %s\n  detected at %s\n\n", strings.Title(res.Provider), res.RootPath)
				} else {
					fmt.Printf("○ %s\n  not detected\n\n", strings.Title(res.Provider))
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output providers list in JSON format")
	cmd.Flags().BoolVar(&capFlag, "capabilities", false, "Display provider feature capability matrix")
	return cmd
}

func newScanCmd() *cobra.Command {
	var providerFlag string
	var workspaceFlag string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan providers for safe portable artifacts (read-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			adapters := getAdapters()
			if providerFlag != "" {
				ad, exists := adapters[providerFlag]
				if !exists {
					return fmt.Errorf("unknown provider %s", providerFlag)
				}
				adapters = map[string]adapter.Adapter{providerFlag: ad}
			}

			fmt.Println("AgentPort Scan")
			if workspaceFlag != "" {
				fmt.Printf("Workspace: %s\n", workspaceFlag)
			}
			fmt.Println()

			for name, ad := range adapters {
				res, err := ad.Scan(ctx)
				if err != nil {
					fmt.Printf("%s: scan error: %v\n", strings.Title(name), err)
					continue
				}
				fmt.Printf("%s\n", strings.Title(name))
				fmt.Printf("  %d supported artifacts\n", res.SupportedArtifacts)
				fmt.Printf("  %d unsupported files ignored\n", res.UnsupportedIgnored)
				if res.RejectedBySecurity > 0 {
					fmt.Printf("  %d files rejected by security policy\n", res.RejectedBySecurity)
				}
				fmt.Println()
			}
			fmt.Println("Nothing was changed.")
			return nil
		},
	}
	cmd.Flags().StringVar(&providerFlag, "provider", "", "Scan specific provider (codex, claude, gemini)")
	cmd.Flags().StringVar(&workspaceFlag, "workspace", "", "Target workspace path")
	return cmd
}

func newImportCmd() *cobra.Command {
	var providerFlag string
	var workspaceFlag string
	var allFlag bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import portable context from providers into local canonical vault",
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

			adapters := getAdapters()
			if !allFlag && providerFlag != "" {
				ad, exists := adapters[providerFlag]
				if !exists {
					return fmt.Errorf("unknown provider %s", providerFlag)
				}
				adapters = map[string]adapter.Adapter{providerFlag: ad}
			}

			opCtx := &adapter.OperationContext{
				WorkspacePath: workspaceFlag,
				Scope:         model.ScopeGlobal,
			}
			if workspaceFlag != "" {
				opCtx.Scope = model.ScopeProject
				opCtx.ProjectID = model.ComputeFingerprint(model.KindProjectContext, model.ScopeProject, workspaceFlag, workspaceFlag, nil)[:16]
			}

			allImported := make([]*model.EnvelopeV2, 0)
			for name, ad := range adapters {
				envs, err := ad.ImportV2(ctx, v.Machine.MachineID, opCtx)
				if err != nil {
					fmt.Printf("Error importing from %s: %v\n", name, err)
					continue
				}
				allImported = append(allImported, envs...)
			}

			reconciled, err := reconcile.ReconcileV2(v, allImported)
			if err != nil {
				return fmt.Errorf("reconciliation failed: %w", err)
			}

			tx := v.BeginTx()
			for _, env := range reconciled.Created {
				if err := tx.SaveEntity(env); err != nil {
					_ = tx.Rollback()
					return fmt.Errorf("failed saving created entity %s: %w", env.ID, err)
				}
			}
			for _, env := range reconciled.Updated {
				if err := tx.UpdateEntity(env); err != nil {
					_ = tx.Rollback()
					return fmt.Errorf("failed updating entity %s: %w", env.ID, err)
				}
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("failed committing imported entities: %w", err)
			}

			fmt.Println("Import Reconciliation Summary:")
			fmt.Printf("  Created:   %d\n", len(reconciled.Created))
			fmt.Printf("  Updated:   %d\n", len(reconciled.Updated))
			fmt.Printf("  Unchanged: %d\n", len(reconciled.Unchanged))
			return nil
		},
	}
	cmd.Flags().StringVar(&providerFlag, "provider", "", "Import from specific provider")
	cmd.Flags().StringVar(&workspaceFlag, "workspace", "", "Target workspace path")
	cmd.Flags().BoolVar(&allFlag, "all", false, "Import from all detected providers")
	return cmd
}

func newOptimizeCmd() *cobra.Command {
	var safeFlag bool
	var dryRunFlag bool
	cmd := &cobra.Command{
		Use:   "optimize",
		Short: "Optimize vault state (safe deterministic deduplication)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !safeFlag {
				return fmt.Errorf("--safe flag is required for optimization baseline")
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			opt := optimizer.NewSafeOptimizer()
			res, err := opt.Optimize(v, dryRunFlag)
			if err != nil {
				return err
			}

			fmt.Println("AgentPort Memory Optimization")
			fmt.Println()
			fmt.Printf("Artifacts scanned:        %d\n", res.ScannedCount)
			fmt.Printf("Exact duplicates:          %d\n", res.ExactDuplicatesRemoved)
			fmt.Printf("Provenance entries merged: %d\n", res.ProvenanceEntriesMerged)
			fmt.Println()
			fmt.Printf("Before: %d\n", res.BeforeCount)
			fmt.Printf("After:  %d\n", res.AfterCount)
			fmt.Println()
			if dryRunFlag {
				fmt.Println("(Dry-run mode: no changes were written to vault)")
			} else {
				fmt.Println("No semantic content changed.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&safeFlag, "safe", false, "Perform safe deterministic optimization")
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Preview optimization without modifying vault")
	return cmd
}

func newValidateCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate vault integrity and security boundary",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			res := v.Validate()

			if jsonOutput {
				data, _ := json.MarshalIndent(res, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("AgentPort Vault Validation")
			fmt.Println()
			fmt.Printf("Total Artifacts: %d\n", res.TotalArtifacts)
			fmt.Printf("Valid Artifacts: %d\n", res.ValidArtifacts)
			fmt.Println()

			if res.Healthy {
				fmt.Println("Result: ✓ Vault is valid and secure")
			} else {
				fmt.Println("Result: ✗ Integrity issues detected:")
				for _, errStr := range res.Errors {
					fmt.Printf("  - %s\n", errStr)
				}
				return fmt.Errorf("vault validation failed")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output validation result in JSON format")
	return cmd
}

func newExportCmd() *cobra.Command {
	var providerFlag string
	var dryRunFlag bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export canonical vault context to provider-native files",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			if providerFlag == "" {
				return fmt.Errorf("--provider <name> flag is required")
			}

			adapters := getAdapters()
			ad, exists := adapters[providerFlag]
			if !exists {
				return fmt.Errorf("unknown provider %s", providerFlag)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			b := contextpkg.DefaultTokenBudget()
			cc := contextpkg.NewContextCompiler(b)
			manifest, err := cc.Compile(ctx, v, providerFlag, ad.Capabilities())
			if err != nil {
				return err
			}

			plan, err := ad.PlanExportV2(ctx, manifest)
			if err != nil {
				return err
			}

			fmt.Printf("Export Plan for %s\n\n", strings.Title(providerFlag))
			for _, item := range plan.Items {
				fmt.Printf("[%s] %s -> %s (%s)\n", item.Action, item.SourceArtifactID, item.TargetPath, item.DiffSummary)
			}
			fmt.Println()

			if dryRunFlag {
				fmt.Println("(Dry-run mode: provider files remain untouched)")
				return nil
			}

			applyRes, err := ad.ApplyExport(ctx, plan)
			if err != nil {
				return err
			}

			fmt.Printf("Successfully exported %d artifacts to %s\n", applyRes.AppliedCount, providerFlag)
			if len(applyRes.BackupsCreated) > 0 {
				fmt.Printf("Created %d backups\n", len(applyRes.BackupsCreated))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&providerFlag, "provider", "", "Target provider name (codex, claude, gemini)")
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Plan export without writing changes")
	return cmd
}

func newSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Manage vault backup snapshots",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "create",
		Short: "Create a backup snapshot of current vault state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}
			mgr := snapshot.NewManager(cfg)
			meta, err := mgr.CreateSnapshot(v, "Manual user snapshot")
			if err != nil {
				return err
			}
			fmt.Printf("Created snapshot %s (%d artifacts)\n", meta.SnapshotID, meta.ArtifactCount)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all vault snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			mgr := snapshot.NewManager(cfg)
			snaps, err := mgr.ListSnapshots()
			if err != nil {
				return err
			}
			fmt.Println("Vault Snapshots")
			fmt.Println()
			for _, s := range snaps {
				fmt.Printf("%s | %d artifacts | %s | %s\n", s.SnapshotID, s.ArtifactCount, s.CreatedAt.Format("2006-01-02 15:04:05"), s.Reason)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "restore <snapshot-id>",
		Short: "Restore vault state from snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}
			mgr := snapshot.NewManager(cfg)
			if err := mgr.RestoreSnapshot(v, args[0]); err != nil {
				return err
			}
			fmt.Printf("Successfully restored snapshot %s\n", args[0])
			return nil
		},
	})

	return cmd
}

func newRemoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage Git synchronization remote repository",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "set <url>",
		Short: "Configure Git remote repository URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			store := gitstore.New(cfg)
			if err := store.SetRemote(ctx, args[0]); err != nil {
				return err
			}
			fmt.Printf("Configured Git sync remote: %s\n", args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show configured Git remote repository URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			store := gitstore.New(cfg)
			url, err := store.GetRemote(ctx)
			if err != nil || url == "" {
				fmt.Println("No remote repository configured.")
				return nil
			}
			fmt.Printf("Remote origin: %s\n", url)
			return nil
		},
	})

	return cmd
}

func newSyncCmd() *cobra.Command {
	var dryRunFlag bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize encrypted vault with Git remote repository",
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

			store := gitstore.New(cfg)
			res, err := store.Sync(ctx, v, dryRunFlag)
			if err != nil {
				return err
			}

			fmt.Println("AgentPort Sync")
			fmt.Println()
			fmt.Printf("Status:               %s\n", res.Message)
			fmt.Printf("Objects Encrypted:    %d\n", res.ObjectsEncryptedCount)
			fmt.Printf("Objects Decrypted:    %d\n", res.ObjectsDecryptedCount)
			if res.CommitSHA != "" {
				fmt.Printf("Commit SHA:           %s\n", res.CommitSHA)
			}
			for _, w := range res.Warnings {
				fmt.Printf("Warning:              %s\n", w)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Preview synchronization without committing or pushing")
	return cmd
}

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage local Age encryption keys",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show public key recipient information",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}
			fmt.Printf("Encryption Recipient (Public): %s\n", v.Metadata.Recipient)
			return nil
		},
	})

	var outputFlag string
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export private Age identity key to a secure file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputFlag == "" {
				return fmt.Errorf("--output <file> path is required")
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			fmt.Println("WARNING: Exporting your private encryption key grants full access to decrypt your vault.")
			if err := crypt.SaveIdentityToFile(v.Key.Identity, outputFlag); err != nil {
				return err
			}
			fmt.Printf("Identity key exported securely to: %s\n", outputFlag)
			return nil
		},
	}
	exportCmd.Flags().StringVar(&outputFlag, "output", "", "Output file path for private identity key")
	cmd.AddCommand(exportCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "import <path>",
		Short: "Import private Age identity key from a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			_ = cfg.EnsureDirectories()

			kp, err := crypt.LoadIdentityFromFile(args[0])
			if err != nil {
				return fmt.Errorf("failed parsing identity key from %s: %w", args[0], err)
			}

			// Verify imported key matches vault recipient if vault exists
			vaultMetaPath := filepath.Join(cfg.VaultDir, "vault.json")
			if data, err := os.ReadFile(vaultMetaPath); err == nil {
				meta := &vault.VaultMetadata{}
				if err := json.Unmarshal(data, meta); err == nil && meta.Recipient != "" {
					if meta.Recipient != kp.Recipient.String() {
						return fmt.Errorf("%w: imported key recipient %s does not match vault recipient %s", vault.ErrRecipientKeyMismatch, kp.Recipient.String(), meta.Recipient)
					}
				}
			}

			keyPath := fmt.Sprintf("%s/identity.age", cfg.KeysDir)
			if err := crypt.SaveIdentityToFile(kp.Identity, keyPath); err != nil {
				return fmt.Errorf("failed saving imported key: %w", err)
			}

			fmt.Printf("Successfully imported identity key (Recipient: %s)\n", kp.Recipient.String())
			return nil
		},
	})

	return cmd
}

func newCompileCmd() *cobra.Command {
	var providerFlag string
	var budgetFlag int
	var dryRunFlag bool
	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile canonical vault context for a target provider within a token budget",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			if providerFlag == "" {
				return fmt.Errorf("--provider <name> flag is required")
			}

			adapters := getAdapters()
			ad, exists := adapters[providerFlag]
			if !exists {
				return fmt.Errorf("unknown provider %s", providerFlag)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			b := contextpkg.DefaultTokenBudget()
			if budgetFlag > 0 {
				b.MaxTokens = budgetFlag
			}

			cc := contextpkg.NewContextCompiler(b)
			manifest, err := cc.Compile(ctx, v, providerFlag, ad.Capabilities())
			if err != nil {
				return err
			}

			fmt.Printf("AgentPort Context Compiler (%s)\n\n", strings.Title(providerFlag))
			fmt.Printf("State Root: %s\n", manifest.StateRoot)
			fmt.Printf("Budget:     %d tokens\n", b.MaxTokens)
			fmt.Printf("Estimated:  %d tokens\n\n", manifest.TotalTokensEst)

			fmt.Println("Included Entities:")
			for _, item := range manifest.Items {
				if item.Included {
					fmt.Printf("  ✓ [%s] %s (~%d tokens)\n", item.Kind, item.Title, item.EstTokenCost)
				}
			}

			fmt.Println("\nExcluded Entities:")
			excludedCount := 0
			for _, item := range manifest.Items {
				if !item.Included {
					fmt.Printf("  ○ [%s] %s (%s)\n", item.Kind, item.Title, item.Reason)
					excludedCount++
				}
			}
			if excludedCount == 0 {
				fmt.Println("  (none)")
			}

			if dryRunFlag {
				fmt.Println("\n(Dry-run mode: compile manifest generated successfully)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&providerFlag, "provider", "", "Target provider (codex, claude, gemini)")
	cmd.Flags().IntVar(&budgetFlag, "budget", 12000, "Maximum token budget allocation")
	cmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Preview context compilation manifest")
	return cmd
}

func newMemoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "memory",
		Short: "Manage and analyze atomic canonical memories",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List canonical memories in vault",
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
			fmt.Println("Canonical Memories")
			fmt.Println()
			for _, art := range artifacts {
				if art.Kind == model.KindMemory || art.Kind == model.KindPreference {
					fmt.Printf("ID: %s | Title: %s | Scope: %s\n", art.ID, art.Title, art.Scope)
				}
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "proposals",
		Short: "List persistent proposals generated by memory compiler",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ps := governance.NewProposalStore(cfg)
			proposals, err := ps.ListProposals()
			if err != nil {
				return err
			}
			fmt.Println("Memory Compiler Proposals")
			fmt.Println()
			if len(proposals) == 0 {
				fmt.Println("No proposals stored.")
				return nil
			}
			for _, prop := range proposals {
				fmt.Printf("ID: %s | Op: %s | Status: %s | Confidence: %.2f\n  Rationale: %s\n\n", prop.ID, prop.Operation, prop.Status, prop.Confidence, prop.Rationale)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show <proposal-id>",
		Short: "Display details for a specific memory proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ps := governance.NewProposalStore(cfg)
			prop, exists := ps.GetProposal(args[0])
			if !exists {
				return fmt.Errorf("proposal %s not found", args[0])
			}
			data, _ := json.MarshalIndent(prop, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	})

	var setFlag string
	applyCmd := &cobra.Command{
		Use:   "apply [proposal-id]",
		Short: "Transactionally apply an accepted memory proposal",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			ps := governance.NewProposalStore(cfg)
			var targetProps []*compiler.Proposal

			if len(args) > 0 {
				p, ok := ps.GetProposal(args[0])
				if !ok {
					return fmt.Errorf("proposal %s not found", args[0])
				}
				targetProps = append(targetProps, p)
			} else if setFlag != "" {
				props, _ := ps.ListProposals()
				for _, p := range props {
					if p.ProposalSetID == setFlag {
						targetProps = append(targetProps, p)
					}
				}
			}

			if len(targetProps) == 0 {
				return fmt.Errorf("proposal ID or valid --set flag is required")
			}

			if err := governance.ApplyProposals(v, cfg, targetProps); err != nil {
				return err
			}

			fmt.Printf("✓ Applied %d proposals successfully!\n", len(targetProps))
			return nil
		},
	}
	applyCmd.Flags().StringVar(&setFlag, "set", "", "Apply entire proposal set by set ID")
	cmd.AddCommand(applyCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "review",
		Short: "Review pending proposal sets from Memory Compiler",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ps := governance.NewProposalStore(cfg)
			props, err := ps.ListProposals()
			if err != nil {
				return err
			}
			pendingCount := 0
			fmt.Println("Pending Governance Proposal Sets")
			fmt.Println()
			for _, p := range props {
				if p.Status == compiler.ProposalStatusPending {
					pendingCount++
					fmt.Printf("  • ID: %s | Set: %s | Op: %s | Conf: %.2f\n    Rationale: %s\n\n", p.ID, p.ProposalSetID, p.Operation, p.Confidence, p.Rationale)
				}
			}
			if pendingCount == 0 {
				fmt.Println("Zero pending proposal sets requiring review.")
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "reject <proposal-id>",
		Short: "Reject a memory compiler proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ps := governance.NewProposalStore(cfg)
			prop, exists := ps.GetProposal(args[0])
			if !exists {
				return fmt.Errorf("proposal %s not found", args[0])
			}
			prop.Status = compiler.ProposalStatusRejected
			if err := ps.SaveProposal(prop); err != nil {
				return err
			}
			fmt.Printf("✓ Proposal %s marked as rejected.\n", prop.ID)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "history [entity-id]",
		Short: "View append-only audit event history",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			j := governance.NewJournal(cfg)
			events, err := j.ListEvents()
			if err != nil {
				return err
			}

			fmt.Println("Audit Event History")
			fmt.Println()
			if len(events) == 0 {
				fmt.Println("No audit events recorded.")
				return nil
			}
			for _, evt := range events {
				if len(args) == 0 || evt.TargetID == args[0] || evt.EventID == args[0] {
					fmt.Printf("%s | %s | %s | %s\n", evt.Timestamp.Format("2006-01-02 15:04:05"), evt.Actor, evt.Operation, evt.TargetID)
				}
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "undo <event-id>",
		Short: "Undo a previous canonical state mutation and restore snapshot state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			j := governance.NewJournal(cfg)
			events, err := j.ListEvents()
			if err != nil {
				return err
			}

			var targetEvt *governance.AuditEvent
			for _, evt := range events {
				if evt.EventID == args[0] {
					targetEvt = evt
					break
				}
			}
			if targetEvt == nil {
				return fmt.Errorf("audit event %s not found", args[0])
			}

			if targetEvt.SnapshotID != "" {
				snapMgr := snapshot.NewManager(cfg)
				if err := snapMgr.RestoreSnapshot(v, targetEvt.SnapshotID); err != nil {
					return fmt.Errorf("failed restoring snapshot %s for undo: %w", targetEvt.SnapshotID, err)
				}
			}

			_ = j.RecordEvent(&governance.AuditEvent{
				Actor:      "user",
				Operation:  "UNDO_" + targetEvt.Operation,
				TargetID:   targetEvt.TargetID,
				SnapshotID: targetEvt.SnapshotID,
			})

			fmt.Printf("✓ Event %s undone and state restored successfully!\n", targetEvt.EventID)
			return nil
		},
	})

	return cmd
}
