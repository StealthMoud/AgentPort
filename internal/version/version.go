package version

import (
	"fmt"
	"runtime"
)

var (
	// Version can be set at build time via:
	// -ldflags "-X github.com/StealthMoud/AgentPort/internal/version.Version=v0.1.0-alpha.2 -X github.com/StealthMoud/AgentPort/internal/version.GitCommit=$(git rev-parse --short HEAD)"
	Version   = "v0.1.0-alpha.2"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Full returns detailed version and build environment information.
func Full() string {
	return fmt.Sprintf("agentport %s (commit: %s, built: %s, os/arch: %s/%s)", Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// String returns standard formatted version string.
func String() string {
	if GitCommit != "unknown" && GitCommit != "" {
		commit := GitCommit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		return fmt.Sprintf("agentport %s+%s", Version, commit)
	}
	return fmt.Sprintf("agentport %s", Version)
}
