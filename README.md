# AgentPort

> AgentPort is an open-source portability and synchronization layer for AI-agent memory, instructions, skills, preferences, and context.

AgentPort decouples your AI-agent memory and instructions from vendor-specific walled gardens (`~/.claude`, `~/.codex`, `~/.gemini`), storing them in a secure, provider-independent canonical format that is encrypted client-side and synchronized across machines via Git.

```text
     Codex
       │
     Claude
       │
     Gemini
       │
       ▼
┌─────────────────┐
│ Provider Adapter│
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ AgentPort Canonical State│ (Schema v1: instructions, memories, preferences...)
└────────────┬────────────┘
             │
      Validate & Security Scan
             │
             ▼
┌─────────────────────────┐
│ Encrypted Vault Storage │ (Age X25519 Client-Side Encryption)
└────────────┬────────────┘
             │
             ▼
      Git Sync Repo (Encrypted Objects Only)
             │
       ┌─────┴─────┐
       ▼           ▼
   Computer A   Computer B
```

## Features

- **Provider-Independent State**: Portable canonical schema (Schema v1) for instructions, memories, preferences, skills, and context.
- **Client-Side Encryption**: Vault payloads encrypted using modern Age (X25519) cryptography before leaving your computer.
- **Zero-Trust Git Sync**: Synchronizes via any standard Git repository (GitHub, GitLab, self-hosted, bare Git repo) without exposing plaintext memory.
- **Security Guardrails**: Hard rejection of secrets (`.env`, credentials, SSH keys, PEM keys, API tokens).
- **Safe Deterministic Optimizer**: Eliminates exact duplicate memories and merges provenance without altering semantic meaning.
- **Multi-Provider Support**: Foundation adapters for OpenAI Codex, Claude Code, and Gemini CLI.

## Quick Start

### Build & Installation

```bash
git clone https://github.com/StealthMoud/AgentPort.git
cd AgentPort
go build -o agentport ./cmd/agentport
```

### Usage Workflow

```bash
# 1. Initialize local vault and encryption identity
agentport init

# 2. Check system diagnostics and detected providers
agentport doctor
agentport providers

# 3. Read-only scan of safe portable artifacts
agentport scan

# 4. Import portable context from all detected providers
agentport import --all

# 5. Safe deterministic deduplication
agentport optimize --safe

# 6. Validate vault integrity
agentport validate

# 7. Configure encrypted Git remote and sync
agentport remote set git@github.com:yourname/private-agent-vault.git
agentport sync

# 8. Export canonical context to another provider
agentport export --provider gemini
```

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Vault Specification](docs/vault-format.md)
- [Adapter Contract](docs/adapter-contract.md)
- [Security Model](docs/security-model.md)
- [Roadmap](docs/roadmap.md)

## License

[Apache 2.0](LICENSE)
