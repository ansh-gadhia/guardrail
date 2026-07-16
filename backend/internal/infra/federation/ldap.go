package federation

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// LDAPConfig configures directory (LDAP/Active Directory) authentication.
type LDAPConfig struct {
	URL                string // ldap://host:389 or ldaps://host:636
	BindDN             string // service account for the user search
	BindPassword       string
	BaseDN             string // search base, e.g. ou=people,dc=corp,dc=com
	UserFilter         string // must contain %s for the username, e.g. (uid=%s)
	EmailAttr          string // attribute holding the email (default "mail")
	UsernameAttr       string // attribute holding the login name (default "uid")
	NameAttr           string // display-name attribute (default "cn")
	StartTLS           bool   // issue StartTLS on a plain ldap:// connection
	InsecureSkipVerify bool   // skip TLS verification (lab only)
}

// ldapConn is the slice of *ldap.Conn we use, extracted so tests can substitute
// a fake directory without a live server.
type ldapConn interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// dialFunc opens a connection to the directory.
type dialFunc func(cfg LDAPConfig) (ldapConn, error)

// LDAPAuthenticator authenticates via the classic search-then-bind pattern: bind
// as a service account, find the user entry, then bind as that user with the
// supplied password to verify it.
type LDAPAuthenticator struct {
	cfg  LDAPConfig
	dial dialFunc
}

// NewLDAPAuthenticator builds an authenticator with sensible attribute defaults.
func NewLDAPAuthenticator(cfg LDAPConfig) *LDAPAuthenticator {
	if cfg.EmailAttr == "" {
		cfg.EmailAttr = "mail"
	}
	if cfg.UsernameAttr == "" {
		cfg.UsernameAttr = "uid"
	}
	if cfg.NameAttr == "" {
		cfg.NameAttr = "cn"
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(" + cfg.UsernameAttr + "=%s)"
	}
	return &LDAPAuthenticator{cfg: cfg, dial: dialLDAP}
}

// Authenticate verifies username/password against the directory.
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*iam.ExternalIdentity, error) {
	if password == "" { // unauthenticated (anonymous) bind guard
		return nil, iam.ErrInvalidCredentials
	}
	conn, err := a.dial(a.cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer conn.Close()

	// 1) Bind as the service account to search.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service bind: %w", err)
		}
	}

	// 2) Find the user entry.
	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter, []string{a.cfg.EmailAttr, a.cfg.UsernameAttr, a.cfg.NameAttr}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, iam.ErrInvalidCredentials
	}
	entry := res.Entries[0]

	// 3) Bind as the user to verify the password.
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, iam.ErrInvalidCredentials
	}

	email := entry.GetAttributeValue(a.cfg.EmailAttr)
	if email == "" {
		email = username // fall back to the login when no mail attribute
	}
	return &iam.ExternalIdentity{
		Provider:    "ldap",
		Subject:     entry.DN,
		Email:       strings.ToLower(email),
		Username:    entry.GetAttributeValue(a.cfg.UsernameAttr),
		DisplayName: entry.GetAttributeValue(a.cfg.NameAttr),
	}, nil
}

// dialLDAP is the production dialer over a real *ldap.Conn.
func dialLDAP(cfg LDAPConfig) (ldapConn, error) {
	opts := []ldap.DialOpt{}
	if strings.HasPrefix(cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify})) //nolint:gosec // lab opt-in
	}
	c, err := ldap.DialURL(cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}); err != nil { //nolint:gosec // lab opt-in
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}

var _ iam.PasswordAuthenticator = (*LDAPAuthenticator)(nil)
