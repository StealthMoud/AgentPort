# AgentPort CLI Reference — Phase 6

## Device & Onboarding Commands
- `agentport join <git-remote>`: Request access to join an existing remote vault network using per-device keys.
- `agentport device list`: List all authorized devices in the signed registry chain.
- `agentport device requests`: List pending device pairing requests.
- `agentport device approve <request-id>`: Approve a pending device pairing request.
- `agentport device revoke <device-id>`: Revoke an authorized device.

## Protocol & Status Commands
- `agentport protocol status`: Show current Sync Protocol version (V1 vs V2), vault ID, and registry epoch.
- `agentport protocol migrate`: Perform atomic fail-closed migration to Sync Protocol V2.
- `agentport status`: Display system status, device ID, epoch, and state root.
- `agentport doctor`: Validate device keys, registry signatures, recovery configuration, and lock availability.

## Recovery Commands
- `agentport recovery status`: Check offline recovery authority configuration.
- `agentport recovery export --output <path>`: Export an encrypted recovery bundle file.
- `agentport recover <git-remote> --recovery <bundle-file>`: Perform disaster recovery using an offline recovery bundle.

## Conflict Commands
- `agentport conflicts list`: List active application conflicts.
- `agentport conflicts resolve <conflict-id> --take local|remote`: Resolve a conflict.
