package security

import (
	"bytes"
	"strings"
	"testing"
)

const (
	masterA = "master-key-alpha-at-least-32-bytes-long"
	masterB = "master-key-bravo-at-least-32-bytes-long"
)

// The bug this fixes: the id used to be the constant "env:1", so changing the
// master key produced a different key under the same name. Every row still said
// env:1, Get handed back the new key, and authentication failed — every
// credential and TOTP secret permanently unopenable, with nothing recording
// which key had sealed what.
func TestKEKIDChangesWithTheKey(t *testing.T) {
	a, err := NewEnvKeyProvider(masterA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewEnvKeyProvider(masterB)
	if err != nil {
		t.Fatal(err)
	}
	idA, keyA, _ := a.Active()
	idB, keyB, _ := b.Active()

	if idA == idB {
		t.Fatal("two different master keys produced the same KEK id")
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("two different master keys produced the same KEK")
	}
	if idA == LegacyEnvKEKID {
		t.Errorf("a derived id should not collide with the legacy constant: %q", idA)
	}
	if !strings.HasPrefix(idA, "env:") {
		t.Errorf("id %q should keep the provider prefix", idA)
	}
}

// Deterministic, or a restart would rename every key and strand what it sealed.
func TestKEKIDIsStableAcrossConstruction(t *testing.T) {
	for range 3 {
		p, err := NewEnvKeyProvider(masterA)
		if err != nil {
			t.Fatal(err)
		}
		id, _, _ := p.Active()
		first, _ := NewEnvKeyProvider(masterA)
		wantID, _, _ := first.Active()
		if id != wantID {
			t.Fatalf("id is not deterministic: %q then %q", wantID, id)
		}
	}
}

// The id is written to the database and readable by anyone who can see a
// credential row. It must not be derived from the master key directly.
func TestKEKIDDoesNotLeakTheMasterKey(t *testing.T) {
	p, err := NewEnvKeyProvider(masterA)
	if err != nil {
		t.Fatal(err)
	}
	id, key, _ := p.Active()
	if strings.Contains(id, masterA[:16]) {
		t.Fatal("the KEK id contains master key material")
	}
	// It is a hash of the KEK, so it must not be a prefix of the KEK either.
	if bytes.Contains([]byte(id), key[:8]) {
		t.Fatal("the KEK id contains raw key bytes")
	}
}

// Rows sealed before ids were derived carry "env:1", which names no particular
// key. They must keep opening or the upgrade strands every existing secret.
func TestLegacyKEKIDStillResolves(t *testing.T) {
	p, err := NewEnvKeyProvider(masterA)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Get(LegacyEnvKEKID)
	if err != nil {
		t.Fatalf("the legacy id stopped resolving: %v", err)
	}
	_, key, _ := p.Active()
	if !bytes.Equal(got, key) {
		t.Fatal("the legacy id resolved to something other than the current key")
	}
}

func TestPreviousKeyIsResolvableForRotation(t *testing.T) {
	p, err := NewEnvKeyProviderWithPrevious(masterB, masterA)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := NewEnvKeyProvider(masterA)
	oldID, oldKey, _ := old.Active()

	if p.Previous() != oldID {
		t.Fatalf("Previous() = %q, want the old key's id %q", p.Previous(), oldID)
	}
	got, err := p.Get(oldID)
	if err != nil {
		t.Fatalf("the previous key did not resolve: %v", err)
	}
	if !bytes.Equal(got, oldKey) {
		t.Fatal("the previous id resolved to the wrong key")
	}
	// And the new key is still the active one.
	newID, _, _ := p.Active()
	if newID == oldID {
		t.Fatal("rotation left the active id unchanged")
	}
}

// An id naming a key this process does not hold must be an error, not a guess.
// Trying keys until one works is how a caller ends up decrypting with a key
// nobody chose.
func TestUnknownKEKIDIsRefused(t *testing.T) {
	p, err := NewEnvKeyProvider(masterA)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"env:deadbeefcafe", "kms:arn:whatever", "", "env:"} {
		if _, err := p.Get(id); err == nil {
			t.Errorf("Get(%q) returned a key", id)
		}
	}
	// Without a previous key configured, the previous id is empty and must not
	// become a wildcard that matches Get("").
	if _, err := p.Get(p.Previous()); err == nil {
		t.Error(`Get("") resolved when no previous key is configured`)
	}
}

func TestSamePreviousKeyIsRefused(t *testing.T) {
	if _, err := NewEnvKeyProviderWithPrevious(masterA, masterA); err == nil {
		t.Fatal("a previous key identical to the current one was accepted")
	}
}

func TestShortKeysAreRefused(t *testing.T) {
	if _, err := NewEnvKeyProvider("too-short"); err == nil {
		t.Error("a short master key was accepted")
	}
	if _, err := NewEnvKeyProviderWithPrevious(masterA, "too-short"); err == nil {
		t.Error("a short previous key was accepted")
	}
}
