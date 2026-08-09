# Changelog

All notable changes to AgentPort will be documented in this file.

## [v0.1.0-alpha.1] - 2026-08-09

### Added
- Complete Basement / Foundation implementation.
- Canonical Schema v1 artifact specification, SHA-256 content fingerprinting, and normalization engine.
- Modern client-side Age (X25519) encryption and local key management commands.
- Security scanner rejecting PEM private keys, AWS credentials, API tokens, and credentials files.
- Filesystem safety package (`fsutil`) with atomic writes, path traversal guards, and symlink escape verification.
- Provider foundation adapters for Codex, Claude Code, and Gemini CLI.
- Safe deterministic memory optimizer (deduplication & provenance merging without semantic rewriting).
- Vault snapshot creation, listing, and restoration engine.
- Git-backed encrypted vault synchronization with fast-forward and divergence detection.
- Complete E2E cross-machine and cross-provider portability integration test suite.
