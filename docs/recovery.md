# AgentPort Offline Recovery Authority & Disaster Recovery

## Recovery Authority
A dedicated offline recovery authority keypair is generated during vault genesis.
- **Encryption**: Active state is encrypted for all active device recipients + recovery Age recipient.
- **Signing**: Emergency recovery registry epochs are signed using the recovery Ed25519 signing key (`agentport/recovery/v2`).
- Private recovery credentials are NEVER synchronized to Git.

## Recovery Bundle
Exported via `agentport recovery export --output <path> [--passphrase <pass>]`.
Stores encrypted private recovery keys. Passphrase protection wraps content via Age Scrypt identity.

## Disaster Recovery Command
If all authorized devices are lost, run:
```bash
agentport recover <git-remote> --recovery <bundle-file>
```
Disaster recovery initializes a new device, signs a new recovery registry epoch, revokes lost devices, re-encrypts current vault state for the new device + recovery recipient, and publishes updated catalogs.
