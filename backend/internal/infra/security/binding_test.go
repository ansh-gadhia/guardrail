package security

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func newBindingSigner(t *testing.T) *BindingSigner {
	t.Helper()
	b, err := NewBindingSigner(strings.Repeat("m", 32))
	if err != nil {
		t.Fatalf("NewBindingSigner: %v", err)
	}
	return b
}

func TestBindingSignVerifyRoundTrip(t *testing.T) {
	b := newBindingSigner(t)
	dev, cred, user := uuid.New(), uuid.New(), uuid.New()

	mac := b.Sign("device", dev, cred, user)
	if !b.Verify(mac, "device", dev, cred, user) {
		t.Fatal("a signature this signer just produced did not verify")
	}
	if len(mac) != 32 {
		t.Errorf("mac is %d bytes, want 32 (HMAC-SHA256)", len(mac))
	}
}

// The attack this exists to stop: point a device you can reach at a credential
// you may not have, by inserting a binding row by hand.
func TestBindingRepointIsRejected(t *testing.T) {
	b := newBindingSigner(t)
	myDevice, myUser := uuid.New(), uuid.New()
	myCred, domainAdminCred := uuid.New(), uuid.New()

	// The legitimate binding, signed when GuardRail wrote it.
	mac := b.Sign("device", myDevice, myCred, myUser)

	// The attacker repoints it at the domain admin credential, keeping the
	// signature — the only part they cannot forge.
	if b.Verify(mac, "device", myDevice, domainAdminCred, myUser) {
		t.Fatal("a repointed binding verified: the MAC does not cover credential_id")
	}
}

func TestBindingMACCoversEveryField(t *testing.T) {
	b := newBindingSigner(t)
	parent, cred, user := uuid.New(), uuid.New(), uuid.New()
	mac := b.Sign("device", parent, cred, user)

	other := uuid.New()
	cases := []struct {
		name               string
		scope              string
		parent, cred, user uuid.UUID
	}{
		{"different parent", "device", other, cred, user},
		{"different credential", "device", parent, other, user},
		{"different user", "device", parent, cred, other},
		// A row lifted from device_credentials into group_credentials.
		{"different scope", "group", parent, cred, user},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if b.Verify(mac, c.scope, c.parent, c.cred, c.user) {
				t.Errorf("%s still verified — that field is not covered", c.name)
			}
		})
	}
}

// A shared binding stores the zero UUID for user_id. It must not be
// interchangeable with a real person's binding in either direction.
func TestSharedAndPerUserBindingsAreDistinct(t *testing.T) {
	b := newBindingSigner(t)
	dev, cred, user := uuid.New(), uuid.New(), uuid.New()

	shared := b.Sign("device", dev, cred, uuid.Nil)
	perUser := b.Sign("device", dev, cred, user)

	if b.Verify(shared, "device", dev, cred, user) {
		t.Error("a shared binding verified as one person's")
	}
	if b.Verify(perUser, "device", dev, cred, uuid.Nil) {
		t.Error("a person's binding verified as the shared one")
	}
}

// An unsigned row must never be treated as valid by Verify itself. Tolerating
// one is a decision a caller has to make explicitly, so that "not yet signed"
// cannot quietly become "trusted".
func TestEmptyMACNeverVerifies(t *testing.T) {
	b := newBindingSigner(t)
	dev, cred, user := uuid.New(), uuid.New(), uuid.New()
	for _, mac := range [][]byte{nil, {}, make([]byte, 32)} {
		if b.Verify(mac, "device", dev, cred, user) {
			t.Errorf("an empty or zero MAC verified (%d bytes)", len(mac))
		}
	}
}

// The binding subkey must not equal the vault KEK derived from the same master
// key: two jobs, two keys, neither usable in the other's place.
func TestBindingKeyIsDisjointFromTheKEK(t *testing.T) {
	const master = "the-same-master-key-for-both----"
	b, err := NewBindingSigner(master)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := NewEnvKeyProvider(master)
	if err != nil {
		t.Fatal(err)
	}
	_, kek, err := kp.Active()
	if err != nil {
		t.Fatal(err)
	}
	if string(b.key) == string(kek) {
		t.Fatal("the binding subkey is the vault KEK")
	}
}

func TestShortMasterKeyIsRefused(t *testing.T) {
	if _, err := NewBindingSigner("too-short"); err == nil {
		t.Fatal("a short master key was accepted")
	}
}
