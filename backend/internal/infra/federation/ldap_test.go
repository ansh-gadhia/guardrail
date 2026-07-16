package federation

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// fakeLDAP is an in-memory directory implementing ldapConn: one service account
// plus one user entry, verifying the search-then-bind pattern.
type fakeLDAP struct {
	serviceDN, servicePW string
	userDN, userPW       string
	userEntry            *ldap.Entry
	boundAs              string
}

func (f *fakeLDAP) Bind(dn, pw string) error {
	switch {
	case dn == f.serviceDN && pw == f.servicePW:
		f.boundAs = dn
		return nil
	case dn == f.userDN && pw == f.userPW:
		f.boundAs = dn
		return nil
	default:
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	}
}

func (f *fakeLDAP) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	// The service account must be bound before searching.
	if f.boundAs != f.serviceDN {
		return nil, errors.New("not bound for search")
	}
	if f.userEntry == nil {
		return &ldap.SearchResult{Entries: nil}, nil
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{f.userEntry}}, nil
}

func (f *fakeLDAP) Close() error { return nil }

func newFakeDir() *fakeLDAP {
	return &fakeLDAP{
		serviceDN: "cn=svc,dc=corp", servicePW: "svcpw",
		userDN: "uid=bob,ou=people,dc=corp", userPW: "bobpass",
		userEntry: &ldap.Entry{
			DN: "uid=bob,ou=people,dc=corp",
			Attributes: []*ldap.EntryAttribute{
				{Name: "mail", Values: []string{"bob@corp.example"}},
				{Name: "uid", Values: []string{"bob"}},
				{Name: "cn", Values: []string{"Bob Corp"}},
			},
		},
	}
}

func newTestAuthenticator(dir *fakeLDAP) *LDAPAuthenticator {
	a := NewLDAPAuthenticator(LDAPConfig{
		URL: "ldap://x", BindDN: "cn=svc,dc=corp", BindPassword: "svcpw",
		BaseDN: "dc=corp", UserFilter: "(uid=%s)",
	})
	a.dial = func(LDAPConfig) (ldapConn, error) { return dir, nil }
	return a
}

func TestLDAP_AuthenticateSuccess(t *testing.T) {
	a := newTestAuthenticator(newFakeDir())
	ext, err := a.Authenticate(context.Background(), "bob", "bobpass")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if ext.Email != "bob@corp.example" || ext.Username != "bob" || ext.DisplayName != "Bob Corp" {
		t.Fatalf("identity mismatch: %+v", ext)
	}
	if ext.Subject != "uid=bob,ou=people,dc=corp" || ext.Provider != "ldap" {
		t.Fatalf("subject/provider mismatch: %+v", ext)
	}
}

func TestLDAP_WrongPassword(t *testing.T) {
	a := newTestAuthenticator(newFakeDir())
	if _, err := a.Authenticate(context.Background(), "bob", "wrong"); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLDAP_EmptyPasswordRejected(t *testing.T) {
	a := newTestAuthenticator(newFakeDir())
	// Guards against LDAP "unauthenticated bind" accepting an empty password.
	if _, err := a.Authenticate(context.Background(), "bob", ""); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("empty password must be rejected, got %v", err)
	}
}

func TestLDAP_UserNotFound(t *testing.T) {
	dir := newFakeDir()
	dir.userEntry = nil // search returns a nil entry -> len!=1 path via empty entries
	a := NewLDAPAuthenticator(LDAPConfig{URL: "ldap://x", BindDN: "cn=svc,dc=corp", BindPassword: "svcpw", BaseDN: "dc=corp"})
	a.dial = func(LDAPConfig) (ldapConn, error) {
		return &fakeLDAP{serviceDN: "cn=svc,dc=corp", servicePW: "svcpw"}, nil
	}
	if _, err := a.Authenticate(context.Background(), "ghost", "x"); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	_ = dir
}
