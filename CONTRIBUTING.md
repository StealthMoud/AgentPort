# Contributing to AgentPort

We welcome contributions to AgentPort!

## Development Guidelines

1. **Go 1.26 Baseline**: Ensure Go 1.26 or newer is installed.
2. **Code Hygiene**: Run `gofmt -s -w .` and `go vet ./...` before submitting PRs.
3. **Tests Required**: Every security boundary, format parser, and adapter must include unit tests. Ensure `go test ./...` passes cleanly.
4. **Security First**: Never bypass client-side encryption or secret scanner rules.
