# AgentPort Device Registry Specification

## Overview
The device registry is a cryptographically authenticated, epoch-based record of authorized devices.

## Registry Epoch Layout
Each registry epoch (`epoch-00000N.json`) contains:
- `protocol_version`: `"2.0"`
- `vault_id`: Stable vault identifier (`apv_...`)
- `epoch`: Sequential integer (`1, 2, 3...`)
- `previous_registry_hash`: SHA-256 hash of canonical previous epoch bytes
- `active_devices`: Map of active `DeviceRecord`s
- `revoked_devices`: Map of revoked `DeviceRecord`s
- `signer_device_id`: Device ID of the active device signing this epoch
- `created_at`: UTC timestamp
- `signature`: Ed25519 signature over canonical payload with domain `agentport/registry/v2`

## Validation Invariants
1. `epoch == previous.epoch + 1`
2. `previous_registry_hash == SHA-256(canonical(previous))`
3. Signer must be active in previous epoch (or genesis signer/recovery authority for epoch 1).
4. `DeviceID`, `AgeRecipient`, and `SigningPublicKey` must be unique across all active devices.
5. Local rollback check: Rejects incoming registry if `epoch < local_highest_epoch`.
