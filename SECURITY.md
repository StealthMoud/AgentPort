# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in AgentPort (such as a secret leak, encryption boundary bypass, or path traversal flaw), please report it responsibly by contacting the maintainers directly or opening a private disclosure.

## Security Guarantees

- **Client-Side Encryption**: Personal state is encrypted with Age (X25519) before synchronization.
- **Secret Protection**: Automatic rejection of PEM keys, AWS credentials, API tokens, and `.env` files.
- **No External Telemetry**: Zero network requests to third-party servers.
- **Credential Operational Security**: Complete prohibition against printing, logging, displaying, or embedding secrets, tokens, or credential store dumps in source code, diagnostic logs, command output, scripts, or commit history.

## Operational Security Guidelines

1. Never log or output authentication material (tokens, passwords, private keys, session cookies).
2. All secret scanning and security diagnostics must redact token values in output.
3. System credential helpers (`osxkeychain`, `git-credential`) must be used without printing sensitive strings.
4. If a credential is discovered in logs or diagnostic outputs:
   - Stop using it immediately.
   - Revoke/rotate the credential.
   - Remove it from all logs, artifacts, and build histories.
