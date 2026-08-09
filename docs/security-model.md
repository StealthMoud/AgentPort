# AgentPort Security Model

## Threat Model & Guarantees

AgentPort deals with sensitive developer context and agent memories across machines. Security is built into the architecture.

### Threat Mitigations

1. **Accidental Secret Syncing**: Secret files (`.env`, `credentials`, `id_rsa`, `*.pem`) and high-entropy secret patterns (PEM keys, AWS credentials, API tokens, Bearer tokens) are detected and hard-rejected before canonical persistence and Git sync.
2. **Untrusted Remote Git Exposure**: Private Git repositories are NOT treated as the sole security boundary. All artifacts are encrypted client-side using Age (X25519) before hitting Git.
3. **Path Traversal & Symlink Escape**: `fsutil` prevents directory traversal (`../`) and verifies resolved symlinks remain inside configured roots.
4. **Atomic Writes**: Writes to vault metadata and provider targets use temp files + atomic renames to prevent partial state corruption.
5. **No Telemetry**: AgentPort performs zero external network requests, zero crash reporting, and zero telemetry. Memory data travels ONLY to the user's explicitly configured Git remote.
