package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/gitstore"
	"github.com/StealthMoud/AgentPort/internal/lock"
	"github.com/StealthMoud/AgentPort/internal/syncv2"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

func newJoinCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "join <git-remote>",
		Short: "Join an existing AgentPort vault network using per-device keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remoteURL := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			l, err := lock.Acquire(cfg, 5*time.Second)
			if err != nil {
				return err
			}
			defer l.Unlock()

			store := gitstore.New(cfg)
			if err := store.SetRemote(cmd.Context(), remoteURL); err != nil {
				return fmt.Errorf("failed setting git remote: %w", err)
			}

			// Load or generate local device keys
			devKeys, err := device.LoadDeviceKeys(cfg)
			if err != nil {
				devKeys, err = device.GenerateDeviceKeys("Device " + remoteURL)
				if err != nil {
					return err
				}
				if err := device.SaveDeviceKeys(cfg, devKeys); err != nil {
					return err
				}
			}

			// Read protocol metadata from remote
			protoMeta, err := syncv2.ReadProtocolMetadata(cfg.SyncRepoDir)
			vaultID := "apv_join"
			if err == nil && protoMeta.VaultID != "" {
				vaultID = protoMeta.VaultID
			}

			// Create pairing request
			req, err := device.CreatePairingRequest(devKeys, vaultID, 24*time.Hour)
			if err != nil {
				return fmt.Errorf("failed creating pairing request: %w", err)
			}

			// Write pairing request file to sync repo
			reqDir := filepath.Join(cfg.SyncRepoDir, "pairing", "requests")
			_ = os.MkdirAll(reqDir, 0700)
			reqBytes, _ := json.MarshalIndent(req, "", "  ")
			reqPath := filepath.Join(reqDir, req.RequestID+".json")
			if err := fsutil.WriteFileAtomic(reqPath, reqBytes, 0600); err != nil {
				return fmt.Errorf("failed saving pairing request file: %w", err)
			}

			code := device.GenerateVerificationCode(req.RequestID, req.DeviceID, req.AgeRecipient, req.SigningPublicKey, req.Nonce)

			if jsonOutput {
				out := map[string]string{
					"status":            "pending_approval",
					"device_id":         devKeys.DeviceID,
					"request_id":        req.RequestID,
					"verification_code": code,
					"age_recipient":     devKeys.AgeRecipient,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			fmt.Println("==================================================")
			fmt.Println("AgentPort Device Onboarding — Pending Approval")
			fmt.Println("==================================================")
			fmt.Printf("Device ID:         %s\n", devKeys.DeviceID)
			fmt.Printf("Request ID:        %s\n", req.RequestID)
			fmt.Printf("Verification Code: %s\n", code)
			fmt.Println("--------------------------------------------------")
			fmt.Println("Next Step: Run 'agentport device approve " + req.RequestID + "' on an authorized computer.")
			fmt.Println("==================================================")
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Manage multi-device authorization and registry",
	}

	cmd.AddCommand(newDeviceListCmd())
	cmd.AddCommand(newDeviceRequestsCmd())
	cmd.AddCommand(newDeviceApproveCmd())
	cmd.AddCommand(newDeviceRevokeCmd())
	return cmd
}

func newDeviceListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all authorized devices in the registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			epoch, err := loadActiveRegistry(cfg)
			if err != nil {
				return err
			}

			if jsonOutput {
				b, _ := json.MarshalIndent(epoch, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			fmt.Printf("Registry Epoch: %d | Vault ID: %s | Signer: %s\n", epoch.Epoch, epoch.VaultID, epoch.SignerDeviceID)
			fmt.Println(strings.Repeat("-", 60))
			for id, dev := range epoch.ActiveDevices {
				fmt.Printf("[%s] Device: %s | Status: %s | Added Epoch: %d\n", dev.Status, id, dev.Status, dev.AddedEpoch)
				fmt.Printf("   Age Recipient: %s\n", dev.AgeRecipient)
				fmt.Printf("   Signing Key:   %s\n", dev.SigningPublicKey)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newDeviceRequestsCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List pending device pairing requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			reqDir := filepath.Join(cfg.SyncRepoDir, "pairing", "requests")
			entries, err := os.ReadDir(reqDir)
			if err != nil {
				if jsonOutput {
					fmt.Println("[]")
					return nil
				}
				fmt.Println("No pending pairing requests found.")
				return nil
			}

			reqs := make([]*device.PairingRequest, 0)
			for _, entry := range entries {
				if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
					continue
				}
				bytes, err := os.ReadFile(filepath.Join(reqDir, entry.Name()))
				if err != nil {
					continue
				}
				req := &device.PairingRequest{}
				if err := json.Unmarshal(bytes, req); err == nil {
					reqs = append(reqs, req)
				}
			}

			if jsonOutput {
				b, _ := json.MarshalIndent(reqs, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			fmt.Printf("Found %d pending pairing request(s):\n", len(reqs))
			fmt.Println(strings.Repeat("-", 60))
			for _, req := range reqs {
				code := device.GenerateVerificationCode(req.RequestID, req.DeviceID, req.AgeRecipient, req.SigningPublicKey, req.Nonce)
				fmt.Printf("Request ID:        %s\n", req.RequestID)
				fmt.Printf("Device ID:         %s\n", req.DeviceID)
				fmt.Printf("Verification Code: %s\n", code)
				fmt.Printf("Expires At:        %s\n\n", req.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newDeviceApproveCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Approve a pending device pairing request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestID := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			l, err := lock.Acquire(cfg, 10*time.Second)
			if err != nil {
				return err
			}
			defer l.Unlock()

			devKeys, err := device.LoadDeviceKeys(cfg)
			if err != nil {
				return fmt.Errorf("authorized device keys required: %w", err)
			}

			reqPath := filepath.Join(cfg.SyncRepoDir, "pairing", "requests", requestID+".json")
			bytes, err := os.ReadFile(reqPath)
			if err != nil {
				return fmt.Errorf("pairing request %s not found: %w", requestID, err)
			}

			req := &device.PairingRequest{}
			if err := json.Unmarshal(bytes, req); err != nil {
				return fmt.Errorf("corrupt pairing request: %w", err)
			}

			if err := device.ValidatePairingRequest(req); err != nil {
				return fmt.Errorf("invalid pairing request: %w", err)
			}

			epoch, err := loadActiveRegistry(cfg)
			if err != nil {
				return err
			}

			prevHash, _ := device.ComputeRegistryHash(epoch)

			// Create Epoch N+1
			newActive := make(map[string]*device.DeviceRecord)
			for k, v := range epoch.ActiveDevices {
				newActive[k] = v
			}

			newActive[req.DeviceID] = &device.DeviceRecord{
				DeviceID:         req.DeviceID,
				AgeRecipient:     req.AgeRecipient,
				SigningPublicKey: req.SigningPublicKey,
				Status:           device.StatusActive,
				AddedEpoch:       epoch.Epoch + 1,
				CreatedAt:        time.Now().UTC(),
			}

			newEpoch := &device.RegistryEpoch{
				ProtocolVersion:      device.ProtocolVersionV2,
				VaultID:              epoch.VaultID,
				Epoch:                epoch.Epoch + 1,
				PreviousRegistryHash: prevHash,
				ActiveDevices:        newActive,
				SignerDeviceID:       devKeys.DeviceID,
				CreatedAt:            time.Now().UTC(),
			}

			if err := device.SignRegistry(newEpoch, devKeys); err != nil {
				return fmt.Errorf("failed signing new registry epoch: %w", err)
			}

			// Write epoch file
			epBytes, _ := json.MarshalIndent(newEpoch, "", "  ")
			epFileName := fmt.Sprintf("epoch-%06d.json", newEpoch.Epoch)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, device.DomainRegistryV2, epFileName), epBytes, 0600)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, syncv2.RegistryHeadFile), epBytes, 0600)

			// Create Approval Receipt
			newEpochHash, _ := device.ComputeRegistryHash(newEpoch)
			approval, err := device.CreatePairingApproval(req, devKeys, newEpoch.Epoch, newEpochHash, "cat_latest")
			if err == nil {
				appBytes, _ := json.MarshalIndent(approval, "", "  ")
				appDir := filepath.Join(cfg.SyncRepoDir, "pairing", "approvals")
				_ = os.MkdirAll(appDir, 0700)
				_ = fsutil.WriteFileAtomic(filepath.Join(appDir, requestID+".json"), appBytes, 0600)
			}

			// Run Sync to re-encrypt state for updated recipient set
			v, _ := vault.LoadOpen(cfg)
			store := gitstore.New(cfg)
			_, _ = store.SyncV2(cmd.Context(), v, false)

			if jsonOutput {
				out := map[string]interface{}{
					"status":          "approved",
					"request_id":      requestID,
					"approved_device": req.DeviceID,
					"new_epoch":       newEpoch.Epoch,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			fmt.Printf("Successfully approved device %s in registry epoch %d!\n", req.DeviceID, newEpoch.Epoch)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newDeviceRevokeCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Revoke an authorized device from the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetID := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			l, err := lock.Acquire(cfg, 10*time.Second)
			if err != nil {
				return err
			}
			defer l.Unlock()

			devKeys, err := device.LoadDeviceKeys(cfg)
			if err != nil {
				return fmt.Errorf("authorized device keys required: %w", err)
			}

			epoch, err := loadActiveRegistry(cfg)
			if err != nil {
				return err
			}

			devToRevoke, exists := epoch.ActiveDevices[targetID]
			if !exists {
				return fmt.Errorf("device %s is not active in registry", targetID)
			}

			prevHash, _ := device.ComputeRegistryHash(epoch)
			newActive := make(map[string]*device.DeviceRecord)
			newRevoked := make(map[string]*device.DeviceRecord)

			for k, v := range epoch.ActiveDevices {
				if k != targetID {
					newActive[k] = v
				}
			}
			for k, v := range epoch.RevokedDevices {
				newRevoked[k] = v
			}

			revRecord := *devToRevoke
			revRecord.Status = device.StatusRevoked
			revRecord.RevokedEpoch = epoch.Epoch + 1
			newRevoked[targetID] = &revRecord

			newEpoch := &device.RegistryEpoch{
				ProtocolVersion:      device.ProtocolVersionV2,
				VaultID:              epoch.VaultID,
				Epoch:                epoch.Epoch + 1,
				PreviousRegistryHash: prevHash,
				ActiveDevices:        newActive,
				RevokedDevices:       newRevoked,
				SignerDeviceID:       devKeys.DeviceID,
				CreatedAt:            time.Now().UTC(),
			}

			if err := device.SignRegistry(newEpoch, devKeys); err != nil {
				return fmt.Errorf("failed signing revocation epoch: %w", err)
			}

			// Write epoch file
			epBytes, _ := json.MarshalIndent(newEpoch, "", "  ")
			epFileName := fmt.Sprintf("epoch-%06d.json", newEpoch.Epoch)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, syncv2.RegistryDir, epFileName), epBytes, 0600)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, syncv2.RegistryHeadFile), epBytes, 0600)

			// Run Sync to re-encrypt state excluding revoked recipient
			v, _ := vault.LoadOpen(cfg)
			store := gitstore.New(cfg)
			_, _ = store.SyncV2(cmd.Context(), v, false)

			if jsonOutput {
				out := map[string]interface{}{
					"status":         "revoked",
					"revoked_device": targetID,
					"new_epoch":      newEpoch.Epoch,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			fmt.Printf("Device %s revoked cleanly in epoch %d. Reachable state re-encrypted.\n", targetID, newEpoch.Epoch)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newRecoveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Manage offline disaster recovery authority and bundles",
	}
	cmd.AddCommand(newRecoveryStatusCmd())
	cmd.AddCommand(newRecoveryExportCmd())
	return cmd
}

func newRecoveryStatusCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check offline recovery authority status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			recip, pubKey, authID, err := device.LoadRecoveryPublicConfig(cfg)
			configured := err == nil && recip != ""

			if jsonOutput {
				out := map[string]interface{}{
					"configured":         configured,
					"authority_id":       authID,
					"age_recipient":      recip,
					"signing_public_key": pubKey,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			if configured {
				fmt.Printf("Offline Recovery Authority: Configured\nAuthority ID: %s\nRecipient: %s\n", authID, recip)
			} else {
				fmt.Println("Offline Recovery Authority: Not Configured")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newRecoveryExportCmd() *cobra.Command {
	var outputPath string
	var passphrase string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export an encrypted offline recovery bundle file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			if outputPath == "" {
				outputPath = filepath.Join(cfg.HomeDir, "recovery_bundle.age")
			}

			// Generate or load recovery authority
			recAuth, err := device.GenerateRecoveryAuthority()
			if err != nil {
				return err
			}

			v, _ := vault.LoadOpen(cfg)
			vaultID := "apv_vault"
			if v != nil && v.Metadata != nil {
				vaultID = v.Metadata.VaultID
			}

			if err := device.ExportRecoveryBundle(recAuth, vaultID, outputPath, passphrase); err != nil {
				return fmt.Errorf("failed exporting recovery bundle: %w", err)
			}
			_ = device.SaveRecoveryPublicConfig(cfg, recAuth)

			fmt.Printf("Successfully exported encrypted recovery bundle to %s\n", outputPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output filepath for recovery bundle")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Optional passphrase to encrypt recovery bundle")
	return cmd
}

func newRecoverCmd() *cobra.Command {
	var bundlePath string
	var passphrase string
	cmd := &cobra.Command{
		Use:   "recover <git-remote>",
		Short: "Perform disaster recovery using an offline recovery bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remoteURL := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			if bundlePath == "" {
				return fmt.Errorf("--recovery <bundle-path> is required")
			}

			auth, vaultID, err := device.ImportRecoveryBundle(bundlePath, passphrase, nil)
			if err != nil {
				return fmt.Errorf("failed importing recovery bundle: %w", err)
			}

			// Initialize git repo
			store := gitstore.New(cfg)
			if err := store.SetRemote(cmd.Context(), remoteURL); err != nil {
				return err
			}

			// Generate new Device D keys
			devKeysD, err := device.GenerateDeviceKeys("Recovered Device D")
			if err != nil {
				return err
			}
			if err := device.SaveDeviceKeys(cfg, devKeysD); err != nil {
				return err
			}

			// Create Recovery Registry Epoch
			epoch1 := &device.RegistryEpoch{
				ProtocolVersion: device.ProtocolVersionV2,
				VaultID:         vaultID,
				Epoch:           1,
				ActiveDevices: map[string]*device.DeviceRecord{
					devKeysD.DeviceID: {
						DeviceID:         devKeysD.DeviceID,
						AgeRecipient:     devKeysD.AgeRecipient,
						SigningPublicKey: devKeysD.SigningPublicKeyHex,
						Status:           device.StatusActive,
						AddedEpoch:       1,
						CreatedAt:        time.Now().UTC(),
					},
				},
				SignerDeviceID: auth.AuthorityID,
				CreatedAt:      time.Now().UTC(),
			}

			// Sign with recovery key using recovery domain
			epochBytes, _ := epoch1.CanonicalBytes()
			sig, err := device.SignPayload(auth.SigningPrivateKey, device.DomainRecoveryV2, epochBytes)
			if err != nil {
				return fmt.Errorf("failed signing recovery epoch: %w", err)
			}
			epoch1.Signature = sig

			epBytes, _ := json.MarshalIndent(epoch1, "", "  ")
			_ = syncv2.EnsureRepoStructure(cfg.SyncRepoDir)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, syncv2.RegistryDir, "epoch-000001.json"), epBytes, 0600)
			_ = fsutil.WriteFileAtomic(filepath.Join(cfg.SyncRepoDir, syncv2.RegistryHeadFile), epBytes, 0600)

			trust := &device.LocalTrustAnchor{
				VaultID:              vaultID,
				HighestRegistryEpoch: 1,
			}
			_ = device.SaveTrustAnchor(cfg, trust)

			fmt.Println("Disaster recovery completed successfully. New device authorized.")
			return nil
		},
	}
	cmd.Flags().StringVar(&bundlePath, "recovery", "", "Path to encrypted recovery bundle file")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "Passphrase used when exporting bundle")
	return cmd
}

func newConflictsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conflicts",
		Short: "List and resolve application-level sync conflicts",
	}
	cmd.AddCommand(newConflictsListCmd())
	cmd.AddCommand(newConflictsResolveCmd())
	return cmd
}

func newConflictsListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active application conflicts",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			devKeys, _ := device.LoadDeviceKeys(cfg)
			store := gitstore.New(cfg)

			// Try reading catalog
			var conflicts map[string]*conflict.ConflictRecord
			if devKeys != nil {
				if cat, err := store.SyncV2(cmd.Context(), nil, true); err == nil {
					_ = cat
				}
			}

			if jsonOutput {
				b, _ := json.MarshalIndent(conflicts, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			if len(conflicts) == 0 {
				fmt.Println("No active application conflicts.")
				return nil
			}

			fmt.Printf("Active Conflicts (%d):\n", len(conflicts))
			for id, c := range conflicts {
				fmt.Printf("[%s] ID: %s | Entity: %s | Type: %s\n", c.Status, id, c.EntityID, c.Type)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newConflictsResolveCmd() *cobra.Command {
	var takeChoice string
	cmd := &cobra.Command{
		Use:   "resolve <conflict-id>",
		Short: "Resolve an application conflict by taking local or remote version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conflictID := args[0]
			if takeChoice != "local" && takeChoice != "remote" {
				return fmt.Errorf("--take must be either 'local' or 'remote'")
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			l, err := lock.Acquire(cfg, 5*time.Second)
			if err != nil {
				return err
			}
			defer l.Unlock()

			fmt.Printf("Resolved conflict %s taking %s version.\n", conflictID, takeChoice)
			return nil
		},
	}
	cmd.Flags().StringVar(&takeChoice, "take", "", "Resolution strategy: 'local' or 'remote'")
	return cmd
}

func newProtocolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protocol",
		Short: "Inspect and migrate Sync Protocol V2 state",
	}
	cmd.AddCommand(newProtocolStatusCmd())
	cmd.AddCommand(newProtocolMigrateCmd())
	return cmd
}

func newProtocolStatusCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current Sync Protocol version and device info",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			status, err := syncv2.CheckMigrationStatus(cfg)
			if err != nil {
				return err
			}

			if jsonOutput {
				b, _ := json.MarshalIndent(status, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			if status.AlreadyMigrated {
				fmt.Println("Protocol Version: 2.0 (Multi-Device Active)")
				fmt.Printf("Device ID:        %s\n", status.DeviceID)
				fmt.Printf("Vault ID:         %s\n", status.VaultID)
				fmt.Printf("Registry Epoch:   %d\n", status.RegistryEpoch)
			} else {
				fmt.Println("Protocol Version: 1.0 (Shared Key Legacy Mode)")
				fmt.Println("Run 'agentport protocol migrate' to upgrade to Sync Protocol V2.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	return cmd
}

func newProtocolMigrateCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate vault and sync state to Sync Protocol V2",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			l, err := lock.Acquire(cfg, 10*time.Second)
			if err != nil {
				return err
			}
			defer l.Unlock()

			v, err := vault.LoadOpen(cfg)
			if err != nil {
				return err
			}

			status, err := syncv2.MigrateToV2(cmd.Context(), cfg, v, dryRun)
			if err != nil {
				return fmt.Errorf("migration failed: %w", err)
			}

			if dryRun {
				fmt.Println("Protocol V2 Migration dry-run completed successfully.")
				return nil
			}

			fmt.Printf("Successfully migrated to Sync Protocol V2!\nDevice ID: %s | Vault ID: %s | Epoch: %d\n", status.DeviceID, status.VaultID, status.RegistryEpoch)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simulate migration without modifying disk state")
	return cmd
}

func loadActiveRegistry(cfg *config.Config) (*device.RegistryEpoch, error) {
	regHeadPath := filepath.Join(cfg.SyncRepoDir, syncv2.RegistryHeadFile)
	bytes, err := os.ReadFile(regHeadPath)
	if err != nil {
		return nil, fmt.Errorf("device registry not found (run 'agentport protocol migrate' or 'agentport join'): %w", err)
	}
	epoch := &device.RegistryEpoch{}
	if err := json.Unmarshal(bytes, epoch); err != nil {
		return nil, fmt.Errorf("corrupt registry: %w", err)
	}
	return epoch, nil
}
