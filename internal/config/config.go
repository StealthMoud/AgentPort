package config

import (
	"os"
	"path/filepath"
)

const (
	EnvAppHome  = "AGENTPORT_HOME"
	EnvVaultDir = "AGENTPORT_VAULT"

	DefaultDirName = ".agentport"
)

// Config holds resolved path configuration for AgentPort.
type Config struct {
	HomeDir      string
	VaultDir     string
	SyncRepoDir  string
	KeysDir      string
	SnapshotsDir string
}

// Load resolves configuration paths based on environment variables or system defaults.
func Load() (*Config, error) {
	home := os.Getenv(EnvAppHome)
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = filepath.Join(userHome, DefaultDirName)
	}

	vault := os.Getenv(EnvVaultDir)
	if vault == "" {
		vault = filepath.Join(home, "vault")
	}

	cfg := &Config{
		HomeDir:      home,
		VaultDir:     vault,
		SyncRepoDir:  filepath.Join(home, "sync_repo"),
		KeysDir:      filepath.Join(home, "keys"),
		SnapshotsDir: filepath.Join(home, "snapshots"),
	}

	return cfg, nil
}

// EnsureDirectories creates all required base directories with secure permissions (0700).
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.HomeDir,
		c.VaultDir,
		c.SyncRepoDir,
		c.KeysDir,
		c.SnapshotsDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}
