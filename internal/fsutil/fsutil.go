package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrPathTraversal = errors.New("path traversal detected")
	ErrSymlinkEscape = errors.New("symlink escapes root directory")
	ErrFileTooLarge  = errors.New("file exceeds maximum allowed size")
)

const MaxSupportedFileSize int64 = 10 * 1024 * 1024 // 10 MB limit for single portable artifact

// IsSafePath checks if target path remains within root directory.
func IsSafePath(root, target string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("failed to resolve root path: %w", err)
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("failed to resolve target path: %w", err)
	}

	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	if strings.HasPrefix(rel, "..") || rel == ".." {
		return ErrPathTraversal
	}

	return nil
}

// VerifyNoSymlinkEscape checks if target path (resolving symlinks) stays inside root.
func VerifyNoSymlinkEscape(root, target string) error {
	if err := IsSafePath(root, target); err != nil {
		return err
	}

	evalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		if os.IsNotExist(err) {
			// Target does not exist yet (e.g. before write)
			parent := filepath.Dir(target)
			evalParent, errP := filepath.EvalSymlinks(parent)
			if errP != nil && !os.IsNotExist(errP) {
				return errP
			}
			if errP == nil {
				return IsSafePath(root, evalParent)
			}
			return nil
		}
		return err
	}

	evalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		evalRoot = root
	}

	return IsSafePath(evalRoot, evalTarget)
}

// WriteFileAtomic writes data to target file atomically using a temporary file in the same directory.
func WriteFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".agentport_tmp_*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed writing data to temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed closing temp file: %w", err)
	}

	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("failed setting temp file permissions: %w", err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("failed renaming temp file to target: %w", err)
	}

	return nil
}

// ReadFileSafely reads file contents up to maxSize.
func ReadFileSafely(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > maxSize {
		return nil, fmt.Errorf("%w: size %d bytes > max %d", ErrFileTooLarge, info.Size(), maxSize)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(io.LimitReader(f, maxSize+1))
}

// BackupFile creates a timestamped backup of path into backupDir.
func BackupFile(srcPath, backupDir string) (string, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}

	baseName := filepath.Base(srcPath)
	tmpBackup, err := os.CreateTemp(backupDir, baseName+"_bak_*")
	if err != nil {
		return "", err
	}
	defer tmpBackup.Close()

	src, err := os.Open(srcPath)
	if err != nil {
		_ = os.Remove(tmpBackup.Name())
		return "", err
	}
	defer src.Close()

	if _, err := io.Copy(tmpBackup, src); err != nil {
		_ = os.Remove(tmpBackup.Name())
		return "", err
	}

	return tmpBackup.Name(), nil
}
