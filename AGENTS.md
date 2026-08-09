# AGENTS.md — AgentPort Repository Guidelines

## Core System Invariants

1. **Canonical State Primacy**: AgentPort canonical state is the source of truth. Provider-native files are imports and exports, never the canonical database.
2. **Never Sync Secrets**: Secret files (`.env`, `credentials`, `auth`, `id_rsa`, `*.pem`) and credential tokens must be hard-rejected.
3. **Client-Side Encryption**: Vault data must be encrypted using Age before synchronization. Plaintext must never reach Git.
4. **Deterministic Safe Optimizer**: The optimizer baseline must perform only deterministic, non-semantic transformations (fingerprint matching, provenance merging, tag deduplication). Never perform automatic LLM semantic rewriting in the core vault engine.
5. **Atomic Filesystem Safety**: Always write via temporary files (`fsutil.WriteFileAtomic`) with restrictive permissions (`0600`/`0700`) and symlink escape guards.
6. **Cross-Platform Compatibility**: All code must support macOS, Linux, and Windows without platform assumptions.
7. **Strict Credential Operational Security**: Never print, log, echo, or embed authentication credentials, tokens, or credential store dumps in code, scripts, command lines, walkthrough logs, or commit messages. All authentication must use existing system tools or environment variables without revealing secret values.

