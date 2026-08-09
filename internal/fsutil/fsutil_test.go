package fsutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

func TestIsSafePath(t *testing.T) {
	root := t.TempDir()
	safeTarget := filepath.Join(root, "sub", "file.txt")
	unsafeTarget := filepath.Join(root, "..", "outside.txt")

	if err := fsutil.IsSafePath(root, safeTarget); err != nil {
		t.Errorf("expected safe target, got error: %v", err)
	}

	if err := fsutil.IsSafePath(root, unsafeTarget); err == nil {
		t.Errorf("expected path traversal error, got nil")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "test.txt")
	content := []byte("hello world agentport")

	if err := fsutil.WriteFileAtomic(target, content, 0600); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	read, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed reading written file: %v", err)
	}

	if string(read) != string(content) {
		t.Errorf("expected %s, got %s", string(content), string(read))
	}
}

func TestBackupFile(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "original.txt")
	backupDir := filepath.Join(root, "backups")

	content := []byte("important content")
	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatalf("failed writing src file: %v", err)
	}

	bakPath, err := fsutil.BackupFile(src, backupDir)
	if err != nil {
		t.Fatalf("BackupFile failed: %v", err)
	}

	bakContent, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("failed reading backup file: %v", err)
	}

	if string(bakContent) != string(content) {
		t.Errorf("expected backup content %s, got %s", string(content), string(bakContent))
	}
}
