// Package blob stores recording artifacts as opaque bytes. The filesystem
// backend here is the shipped default; it satisfies access.BlobStore, so an
// object-store backend can replace it without touching the recorder.
package blob

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotFound is returned when a key has no stored object.
var ErrNotFound = errors.New("blob: not found")

// FS stores objects as files beneath a root directory. Keys are virtual paths
// ("<org>/<recording>/frames.bin"); each maps to one file.
type FS struct{ root string }

// NewFS constructs a filesystem blob store rooted at dir, creating it if needed.
func NewFS(dir string) (*FS, error) {
	if dir == "" {
		return nil, errors.New("blob: root directory is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("blob: create root: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("blob: resolve root: %w", err)
	}
	return &FS{root: abs}, nil
}

// path resolves a key to a file path, refusing anything that would escape the
// root. Keys are built server-side today, but a store that can be talked out of
// its own directory is one bug away from arbitrary file write.
func (f *FS) path(key string) (string, error) {
	if key == "" || strings.Contains(key, "\x00") {
		return "", fmt.Errorf("blob: invalid key %q", key)
	}
	p := filepath.Join(f.root, filepath.FromSlash(key))
	clean := filepath.Clean(p)
	if clean != f.root && !strings.HasPrefix(clean, f.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("blob: key %q escapes the store root", key)
	}
	return clean, nil
}

// Put writes an object, replacing any existing one. The write goes to a temp
// file and is renamed into place, so a reader never sees a half-written
// recording if the process dies mid-flush.
func (f *FS) Put(_ context.Context, key string, data []byte, _ string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return fmt.Errorf("blob: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("blob: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("blob: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("blob: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return fmt.Errorf("blob: chmod: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("blob: rename: %w", err)
	}
	return nil
}

// Get reads an object, returning ErrNotFound when the key is absent.
func (f *FS) Get(_ context.Context, key string) ([]byte, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("blob: read: %w", err)
	}
	return b, nil
}

// Delete removes an object. Deleting a key that isn't there is not an error —
// retention sweeps should be idempotent.
func (f *FS) Delete(_ context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob: delete: %w", err)
	}
	return nil
}
