# AgentPort Device Management & Lifecycle

## Local Device Key Layout
Device credentials are stored strictly under `~/.agentport/keys/` with restrictive `0600` file permissions:
- `device.age`: X25519 Age private identity (`AGE-SECRET-KEY-1...`).
- `device-signing.key`: Ed25519 private signing key (hex-encoded).
- `device.json`: Local device metadata containing `device_id`, `age_recipient`, `signing_public_key`, and creation timestamp.

## Device Identification
- **DeviceID**: Cryptographic device identifier (`dev_...`) generated randomly per device installation.
- **MachineID**: Machine provenance metadata (`apm_...`) maintained separately for local host identification.

## CLI Commands
- `agentport join <remote>`: Requests access to an existing remote vault.
- `agentport device list`: Displays active and revoked devices in the signed registry chain.
- `agentport device requests`: Lists pending pairing requests.
- `agentport device approve <request-id>`: Approves a pending device request, creates registry epoch N+1, re-encrypts current vault state for the updated recipient set, and pushes transactionally.
- `agentport device revoke <device-id>`: Revokes an active device, advances registry epoch, re-encrypts state excluding revoked recipient, and updates catalog.
