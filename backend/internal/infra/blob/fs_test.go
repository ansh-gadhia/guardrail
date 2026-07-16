package blob

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *FS {
	t.Helper()
	s, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	want := []byte{0xFF, 0xD8, 0xFF, 0x00, 0x01, 0x02}

	if err := s.Put(ctx, "org/rec/frames.bin", want, "application/octet-stream"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "org/rec/frames.bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Get returned %v, want %v", got, want)
	}
}

func TestGetMissingKeyIsNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get(context.Background(), "nope/missing.bin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get of an absent key = %v, want ErrNotFound", err)
	}
}

func TestPutOverwrites(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.Put(ctx, "k", []byte("first"), "")
	if err := s.Put(ctx, "k", []byte("second"), ""); err != nil {
		t.Fatalf("Put (overwrite): %v", err)
	}
	got, _ := s.Get(ctx, "k")
	if string(got) != "second" {
		t.Errorf("after overwrite Get = %q, want %q", got, "second")
	}
}

func TestPutLeavesNoTempFilesBehind(t *testing.T) {
	// The atomic write uses a temp file; it must not litter the store.
	dir := t.TempDir()
	s, err := NewFS(dir)
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	if err := s.Put(context.Background(), "a/b.bin", []byte("x"), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "b.bin" {
			t.Errorf("unexpected leftover file %q", e.Name())
		}
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.Put(ctx, "k", []byte("x"), "")
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Deleting again must not error — retention sweeps re-run.
	if err := s.Delete(ctx, "k"); err != nil {
		t.Errorf("second Delete: %v, want nil", err)
	}
}

func TestKeysCannotEscapeTheRoot(t *testing.T) {
	// A key that climbs out of the root would turn the store into an arbitrary
	// file write primitive.
	dir := t.TempDir()
	s, err := NewFS(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	ctx := context.Background()
	for _, key := range []string{"../escaped.bin", "a/../../escaped.bin", "../../etc/passwd"} {
		if err := s.Put(ctx, key, []byte("pwned"), ""); err == nil {
			t.Errorf("Put(%q) was allowed; it must be refused", key)
		}
		if _, err := s.Get(ctx, key); err == nil {
			t.Errorf("Get(%q) was allowed; it must be refused", key)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.bin")); err == nil {
		t.Error("a file was written outside the store root")
	}
}

func TestEmptyRootIsRejected(t *testing.T) {
	if _, err := NewFS(""); err == nil {
		t.Error("NewFS(\"\") was allowed; a store with no root would write to the cwd")
	}
}
