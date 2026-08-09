package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/config"
)

func TestConfigLoadWithEnv(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "custom_home")
	vaultDir := filepath.Join(tempDir, "custom_vault")

	t.Setenv(config.EnvAppHome, homeDir)
	t.Setenv(config.EnvVaultDir, vaultDir)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.HomeDir != homeDir {
		t.Errorf("expected HomeDir %s, got %s", homeDir, cfg.HomeDir)
	}

	if cfg.VaultDir != vaultDir {
		t.Errorf("expected VaultDir %s, got %s", vaultDir, cfg.VaultDir)
	}

	if err := cfg.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	info, err := os.Stat(homeDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected directory at %s", homeDir)
	}
}
