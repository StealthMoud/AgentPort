# AgentPort Vault Format Specification

## Schema Version 1

### Artifact Model

Every portable object in AgentPort is represented as a canonical artifact JSON object:

```json
{
  "id": "apa_instruction_c9f8a...16",
  "schema_version": "1",
  "kind": "instruction",
  "scope": "global",
  "title": "Code Formatting Preference",
  "content": "Always use Go 1.26 features and strict type safety.",
  "content_type": "text/markdown",
  "lifecycle": "persistent",
  "sensitivity": "normal",
  "created_at": "2026-08-09T20:00:00Z",
  "updated_at": "2026-08-09T20:00:00Z",
  "fingerprint": "c9f8a...64",
  "provenance": [
    {
      "provider": "codex",
      "machine_id": "apm_82f...",
      "source_path": "/Users/user/.codex/instructions.md",
      "imported_at": "2026-08-09T20:00:00Z",
      "source_fingerprint": "c9f8a...64"
    }
  ]
}
```

### Encrypted Git Synchronization Layout

The Git repository contains ONLY encrypted Age payload objects and non-sensitive vault manifest metadata:

```text
.agentport/
    vault.json       (Vault ID, Schema Version, Public Recipient)
    manifest.json    (Opaque Object IDs -> Artifact Fingerprints mapping)

objects/
    <opaque-id>.age  (Age-encrypted ciphertext of canonical artifact JSON)
    <opaque-id>.age
```

No plaintext memory content or private identity keys exist inside the Git repository.
