package lock_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/lock"
)

func TestCrossProcessLock(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		HomeDir:      tempDir,
		VaultDir:     filepath.Join(tempDir, "vault"),
		SyncRepoDir:  filepath.Join(tempDir, "sync"),
		KeysDir:      filepath.Join(tempDir, "keys"),
		SnapshotsDir: filepath.Join(tempDir, "snapshots"),
	}

	l1, err := lock.Acquire(cfg, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}

	// Concurrent lock attempt should fail with ErrLockBusy
	_, err = lock.Acquire(cfg, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("expected second Acquire to fail with ErrLockBusy, but succeeded")
	}

	// Release l1
	if err := l1.Unlock(); err != nil {
		t.Fatalf("l1 Unlock failed: %v", err)
	}

	// Now l2 should succeed
	l2, err := lock.Acquire(cfg, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("subsequent Acquire failed after unlock: %v", err)
	}

	_ = l2.Unlock()
}
