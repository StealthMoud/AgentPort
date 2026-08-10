# AgentPort Sync Protocol V2 Specification

## Overview
AgentPort Sync Protocol V2 replaces shared-private-key models with a secure, multi-device, multi-recipient synchronization architecture built on top of Age encryption and Ed25519 cryptographic signatures.

---

## Key Principles
1. **Per-Device Key Pairs**: Every device generates a unique private X25519 Age encryption key and Ed25519 signing key. No device onboarding requires copying another device's private key.
2. **Authenticated Device Registry**: Epoch-based device registry chain signed by active device signing keys with domain separation (`agentport/registry/v2`).
3. **Multi-Recipient Encryption**: All reachable canonical entity states are encrypted to the set of currently active device recipients + offline recovery recipient.
4. **Immutable Revision Graph**: Entity mutations form an acyclic revision DAG with parent references, enabling 3-way ancestral graph analysis.
5. **Signed Encrypted Catalogs**: Replaces legacy plaintext `manifest.json` with signed, encrypted catalog headers (`agentport/catalog/v2`).
6. **Transport-Only Git**: Git serves strictly as remote transport. Branch divergence triggers application-level graph merge with bounded push retries instead of Git conflict markers.

---

## Remote Directory Structure
```text
protocol.json

registry/
  epoch-000001.json
  epoch-000002.json
  ...

registry-head.json

pairing/
  requests/
    req_<id>.json
  approvals/
    req_<id>.json

catalog-head.json

catalogs/
  cat_<id>.age

objects/
  <opaque-id>.age
```

---

## Transport Metadata Privacy Boundary
`protocol.json` contains only non-sensitive transport metadata:
```json
{
  "protocol_version": "2.0",
  "vault_id": "apv_...",
  "registry_epoch": 1,
  "registry_head_hash": "...",
  "catalog_head_id": "cat_..."
}
```
**Invariant**: No canonical entity titles, memory text, provider instructions, or local filesystem paths appear in plaintext remote transport metadata.
