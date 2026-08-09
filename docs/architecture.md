# AgentPort Architecture

AgentPort is an open-source, provider-independent system for making AI-agent state (instructions, memories, preferences, skills, agents, project context, tool definitions) portable across machines, operating systems, and AI coding agents.

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
│ AgentPort Canonical State│ (Schema v1: instructions, memories, preferences, skills...)
└────────────┬────────────┘
             │
      Validate & Security Scan (Secret rejection, path traversal check)
             │
             ▼
┌─────────────────────────┐
│ Encrypted Vault Storage │ (Age client-side encryption)
└────────────┬────────────┘
             │
             ▼
      Git Store (Bare Git / Remote repo, encrypted objects only)
             │
       ┌─────┴─────┐
       ▼           ▼
   Computer A   Computer B
```

## Architectural Invariants

1. **Canonical State Primacy**: AgentPort canonical state is the source of truth. Provider-native files are imports and exports, never the canonical database.
2. **Client-Side Encryption**: Personal memories are encrypted locally using Age (X25519) before hitting Git. Unencrypted plaintext never enters the sync repository.
3. **Conservative Allowlist**: Provider adapters never recursively copy arbitrary vendor directories. Only safe, recognized instruction and context surfaces are imported.
4. **Deterministic Safe Optimizer**: Optimization deduplicates by SHA-256 content fingerprint and merges provenance. It performs zero semantic alteration or LLM rewriting.
5. **Divergence Protection**: Sync detects Git history divergence and refuses to silently overwrite either side.
