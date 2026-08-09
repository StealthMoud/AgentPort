# AgentPort Provider Adapter Contract

## Overview

Adapters translate between provider-native agent files (Codex, Claude, Gemini, Cursor, Aider, etc.) and AgentPort's canonical data model.

## Interface Contract

```go
type Adapter interface {
	Name() string
	Detect(ctx context.Context) (*DetectResult, error)
	Scan(ctx context.Context) (*ScanResult, error)
	Import(ctx context.Context, machineID string) ([]*model.Artifact, error)
	PlanExport(ctx context.Context, artifacts []*model.Artifact) (*ExportPlan, error)
	ApplyExport(ctx context.Context, plan *ExportPlan) (*ExportResult, error)
	Validate(ctx context.Context) error
}
```

## Rules for New Adapters

1. **Read-Only Operations**: `Detect`, `Scan`, `Import`, and `PlanExport` must be strictly read-only and never modify provider files.
2. **Allowlist Security**: Only read explicitly supported instruction / memory surfaces. Ignore unknown files and reject secrets (`.env`, `credentials`, private keys).
3. **Atomic Export**: All exports performed by `ApplyExport` must be atomic and create backups before modifying existing target files.
4. **Symlink Guard**: Verify target paths do not escape the provider root directory via symlink traversal (`fsutil.VerifyNoSymlinkEscape`).
