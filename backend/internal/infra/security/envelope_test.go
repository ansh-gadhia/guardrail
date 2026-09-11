package security

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/guardrail/guardrail/internal/domain/vault"
)

func newEncryptor(t *testing.T, master string) *EnvelopeEncryptor {
	t.Helper()
	kp, err := NewEnvKeyProvider(master)
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	return NewEnvelopeEncryptor(kp)
}

func TestEnvelope_SealOpenRoundTrip(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	secret := []byte("s3cr3t-device-password!")

	sealed, err := enc.Seal(secret, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, secret) {
		t.Fatal("ciphertext must not contain plaintext")
	}
	// The id is DERIVED from the key, not a constant. It used to be "env:1" for
	// every key, which is what made changing the master key silently destroy the
	// vault: same name, different key, authentication failure on every row.
	if sealed.KEKID == LegacyEnvKEKID {
		t.Fatalf("a new seal used the legacy fixed id %q", sealed.KEKID)
	}
	kp, err := NewEnvKeyProvider(strings.Repeat("m", 32))
	if err != nil {
		t.Fatal(err)
	}
	wantID, _, _ := kp.Active()
	if sealed.KEKID != wantID {
		t.Fatalf("kek id = %q, want the derived id %q", sealed.KEKID, wantID)
	}

	opened, err := enc.Open(sealed, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("round trip mismatch: %q != %q", opened, secret)
	}
}

func TestEnvelope_UniqueCiphertextPerSeal(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	a, _ := enc.Seal([]byte("same"), nil)
	b, _ := enc.Seal([]byte("same"), nil)
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("expected unique ciphertext (random DEK + nonce) per seal")
	}
	if bytes.Equal(a.SecretNonce, b.SecretNonce) {
		t.Fatal("expected unique nonces per seal")
	}
}

func TestEnvelope_TamperedCiphertextFails(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	sealed, _ := enc.Seal([]byte("secret"), nil)
	sealed.Ciphertext[0] ^= 0xFF // flip a bit
	if _, err := enc.Open(sealed, nil); err == nil {
		t.Fatal("expected GCM authentication failure on tampered ciphertext")
	}
}

func TestEnvelope_WrongMasterKeyCannotOpen(t *testing.T) {
	encA := newEncryptor(t, strings.Repeat("a", 32))
	encB := newEncryptor(t, strings.Repeat("b", 32))
	sealed, _ := encA.Seal([]byte("secret"), nil)
	if _, err := encB.Open(sealed, nil); err == nil {
		t.Fatal("expected failure opening with a different master key")
	}
}

func TestEnvelope_RewrapKeepsPlaintext(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	secret := []byte("rotate-me")
	sealed, _ := enc.Seal(secret, nil)
	originalCiphertext := append([]byte(nil), sealed.Ciphertext...)

	rewrapped, err := enc.Rewrap(sealed)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	// Secret ciphertext is unchanged; only the wrapped DEK changes.
	if !bytes.Equal(rewrapped.Ciphertext, originalCiphertext) {
		t.Fatal("rewrap must not change the secret ciphertext")
	}
	opened, err := enc.Open(rewrapped, nil)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("rewrapped secret failed to open: %v", err)
	}
}

func TestEnvKeyProvider_RejectsShortMaster(t *testing.T) {
	if _, err := NewEnvKeyProvider("tooshort"); err == nil {
		t.Fatal("expected rejection of short master key")
	}
}

// TestEnvelope_TransplantedSecretIsRejected is the regression test for C1.
//
// Every credential is sealed under the same KEK, so before associated data was
// bound in, the five stored columns were self-contained AND self-authenticating:
// copied from one credential row onto another they opened cleanly, the gateway
// injected a secret the operator was never entitled to, and the audit trail
// recorded the account name from the destination row — reporting the wrong
// account for a use that really happened.
func TestEnvelope_TransplantedSecretIsRejected(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))

	org := uuid.New()
	credA, credB := uuid.New(), uuid.New()

	// Sealed for credential A — the domain admin, say.
	sealedForA, err := enc.Seal([]byte("domain-admin-secret"), vault.CredentialAAD(org, credA))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealedForA.AADVersion != vault.AADCredentialV1 {
		t.Fatalf("sealed with AAD but recorded version %d", sealedForA.AADVersion)
	}

	// An attacker with row-write copies the five columns onto credential B's
	// row — one they are allowed to resolve.
	transplanted := sealedForA

	if _, err := enc.Open(transplanted, vault.CredentialAAD(org, credB)); err == nil {
		t.Fatal("a transplanted secret opened under another credential's identity")
	}

	// Crossing a tenant boundary must fail too, even for the right credential id.
	if _, err := enc.Open(transplanted, vault.CredentialAAD(uuid.New(), credA)); err == nil {
		t.Fatal("a transplanted secret opened under another organization")
	}

	// And the legitimate open still works, or this would be a denial of service
	// dressed up as a fix.
	got, err := enc.Open(sealedForA, vault.CredentialAAD(org, credA))
	if err != nil {
		t.Fatalf("the credential could not open its own secret: %v", err)
	}
	if string(got) != "domain-admin-secret" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

// Downgrading the recorded version must not disarm the binding. An attacker who
// can write the ciphertext can write the version column beside it, so "open it
// as though it were legacy" has to fail rather than skip the check.
func TestEnvelope_VersionDowngradeDoesNotDisarmAAD(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	org, cred := uuid.New(), uuid.New()

	sealed, err := enc.Seal([]byte("secret"), vault.CredentialAAD(org, cred))
	if err != nil {
		t.Fatal(err)
	}

	downgraded := sealed
	downgraded.AADVersion = vault.AADNone

	if _, err := enc.Open(downgraded, vault.CredentialAAD(org, cred)); err == nil {
		t.Fatal("a version-1 ciphertext opened after being relabelled version 0")
	}
	if _, err := enc.Open(downgraded, nil); err == nil {
		t.Fatal("a version-1 ciphertext opened with no AAD once relabelled")
	}
}

// Legacy ciphertext — sealed before 0036 — must keep opening, or the upgrade
// takes every existing credential offline.
func TestEnvelope_LegacyCiphertextStillOpens(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))

	legacy, err := enc.Seal([]byte("sealed-before-0036"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.AADVersion != vault.AADNone {
		t.Fatalf("sealing with no AAD recorded version %d, want %d", legacy.AADVersion, vault.AADNone)
	}
	got, err := enc.Open(legacy, nil)
	if err != nil {
		t.Fatalf("a legacy secret stopped opening: %v", err)
	}
	if string(got) != "sealed-before-0036" {
		t.Fatalf("round trip mismatch: %q", got)
	}
	// And an AAD supplied for a legacy row is ignored rather than fatal, which is
	// what lets the resolve path pass one unconditionally.
	if _, err := enc.Open(legacy, vault.CredentialAAD(uuid.New(), uuid.New())); err != nil {
		t.Errorf("a legacy secret refused an irrelevant AAD: %v", err)
	}
}
