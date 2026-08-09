package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/StealthMoud/AgentPort/internal/adapter"
	"github.com/StealthMoud/AgentPort/internal/adapter/claude"
	"github.com/StealthMoud/AgentPort/internal/adapter/codex"
	"github.com/StealthMoud/AgentPort/internal/adapter/gemini"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/optimizer"
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

			artifacts := v.ListArtifacts()

			if jsonOutput {
				statusObj := map[string]interface{}{
					"vault_id":       v.Metadata.VaultID,
					"schema_version": v.Metadata.SchemaVersion,
					"artifact_count": len(artifacts),
					"remote_url":     remoteURL,
					"machine_id":     v.Machine.MachineID,
				}
				data, _ := json.MarshalIndent(statusObj, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("AgentPort Status")
			fmt.Println()
			fmt.Printf("Vault:        %s\n", v.Metadata.VaultID)
			fmt.Printf("Schema:       %s\n", v.Metadata.SchemaVersion)
			fmt.Printf("Artifacts:    %d\n", len(artifacts))
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
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "Detect installed AI coding agent providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			adapters := getAdapters()
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
	return cmd
}

func newScanCmd() *cobra.Command {
	var providerFlag string
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
	return cmd
}

func newImportCmd() *cobra.Command {
	var providerFlag string
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

			importedCount := 0
			for name, ad := range adapters {
				arts, err := ad.Import(ctx, v.Machine.MachineID)
				if err != nil {
					fmt.Printf("Error importing from %s: %v\n", name, err)
					continue
				}

				for _, art := range arts {
					if err := v.SaveArtifact(art); err == nil {
						importedCount++
					}
				}
				fmt.Printf("Imported %d artifacts from %s\n", len(arts), name)
			}

			fmt.Println()
			fmt.Printf("Total imported into vault: %d\n", importedCount)
			return nil
		},
	}
	cmd.Flags().StringVar(&providerFlag, "provider", "", "Import from specific provider")
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

			artifacts := v.ListArtifacts()
			plan, err := ad.PlanExport(ctx, artifacts)
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
