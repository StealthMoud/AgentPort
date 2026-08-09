# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in AgentPort (such as a secret leak, encryption boundary bypass, or path traversal flaw), please report it responsibly by contacting the maintainers directly or opening a private disclosure.

## Security Guarantees

- **Client-Side Encryption**: Personal state is encrypted with Age (X25519) before synchronization.
- **Secret Protection**: Automatic rejection of PEM keys, AWS credentials, API tokens, and `.env` files.
- **No External Telemetry**: Zero network requests to third-party servers.
