package security

import (
	"bytes"
	"strings"
	"testing"
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

	sealed, err := enc.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, secret) {
		t.Fatal("ciphertext must not contain plaintext")
	}
	if sealed.KEKID != EnvKEKID {
		t.Fatalf("kek id = %q, want %q", sealed.KEKID, EnvKEKID)
	}

	opened, err := enc.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("round trip mismatch: %q != %q", opened, secret)
	}
}

func TestEnvelope_UniqueCiphertextPerSeal(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	a, _ := enc.Seal([]byte("same"))
	b, _ := enc.Seal([]byte("same"))
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("expected unique ciphertext (random DEK + nonce) per seal")
	}
	if bytes.Equal(a.SecretNonce, b.SecretNonce) {
		t.Fatal("expected unique nonces per seal")
	}
}

func TestEnvelope_TamperedCiphertextFails(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	sealed, _ := enc.Seal([]byte("secret"))
	sealed.Ciphertext[0] ^= 0xFF // flip a bit
	if _, err := enc.Open(sealed); err == nil {
		t.Fatal("expected GCM authentication failure on tampered ciphertext")
	}
}

func TestEnvelope_WrongMasterKeyCannotOpen(t *testing.T) {
	encA := newEncryptor(t, strings.Repeat("a", 32))
	encB := newEncryptor(t, strings.Repeat("b", 32))
	sealed, _ := encA.Seal([]byte("secret"))
	if _, err := encB.Open(sealed); err == nil {
		t.Fatal("expected failure opening with a different master key")
	}
}

func TestEnvelope_RewrapKeepsPlaintext(t *testing.T) {
	enc := newEncryptor(t, strings.Repeat("m", 32))
	secret := []byte("rotate-me")
	sealed, _ := enc.Seal(secret)
	originalCiphertext := append([]byte(nil), sealed.Ciphertext...)

	rewrapped, err := enc.Rewrap(sealed)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	// Secret ciphertext is unchanged; only the wrapped DEK changes.
	if !bytes.Equal(rewrapped.Ciphertext, originalCiphertext) {
		t.Fatal("rewrap must not change the secret ciphertext")
	}
	opened, err := enc.Open(rewrapped)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("rewrapped secret failed to open: %v", err)
	}
}

func TestEnvKeyProvider_RejectsShortMaster(t *testing.T) {
	if _, err := NewEnvKeyProvider("tooshort"); err == nil {
		t.Fatal("expected rejection of short master key")
	}
}
