package lock

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"github.com/StealthMoud/AgentPort/internal/config"
)

var (
	ErrLockBusy = errors.New("vault process lock is busy - another AgentPort process is modifying the vault")
)

type Lock struct {
	flock *flock.Flock
}

// Acquire attempts to acquire a cross-process file lock on the vault with a specified timeout.
func Acquire(cfg *config.Config, timeout time.Duration) (*Lock, error) {
	if err := cfg.EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed ensuring base directories for lock: %w", err)
	}

	lockPath := filepath.Join(cfg.HomeDir, "vault.lock")
	fileLock := flock.New(lockPath)

	if timeout <= 0 {
		locked, err := fileLock.TryLock()
		if err != nil {
			return nil, fmt.Errorf("failed acquiring vault lock: %w", err)
		}
		if !locked {
			return nil, ErrLockBusy
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		retryDelay := 50 * time.Millisecond
		locked, err := fileLock.TryLockContext(ctx, retryDelay)
		if err != nil || !locked {
			return nil, ErrLockBusy
		}
	}

	return &Lock{flock: fileLock}, nil
}

// Unlock releases the cross-process lock.
func (l *Lock) Unlock() error {
	if l == nil || l.flock == nil {
		return nil
	}
	return l.flock.Unlock()
}
