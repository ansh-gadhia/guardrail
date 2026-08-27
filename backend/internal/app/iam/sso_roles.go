package iam

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Role translation between the SIEM's vocabulary and GuardRail's.
//
// This is a TRANSLATION TABLE, not an identity mapping. The two products do not
// share a role vocabulary and should not be made to: the SIEM ranks analysts by
// tier, GuardRail grants named bundles of permissions with an approval rank and
// a device scope attached. Nothing in GuardRail's RBAC is added, removed or
// rewritten by any of this — the table only chooses among roles that already
// exist, and an administrator who has never heard of the SIEM sees the same five
// system roles they always had.

// SIEM role vocabulary, after normalisation.
const (
	siemRoleAdministrator = "ADMINISTRATOR"
	siemRoleL1            = "L1"
	siemRoleL2            = "L2"
	siemRoleL3            = "L3"
)

// Access modes, after normalisation.
const (
	accessReadWrite = "rw"
	accessReadOnly  = "ro"
)

// GuardRail's seeded system roles, by name. Matching is case-insensitive, so an
// override may spell them however it likes.
const (
	RoleSuperAdmin = "Super Admin"
	RoleOrgAdmin   = "Organization Admin"
	RoleOperator   = "Operator"
	RoleAuditor    = "Auditor"
	RoleReadOnly   = "Read-only"
)

// defaultSSORoleTable is the mapping applied when nothing overrides it.
//
// Administrator/read-write lands on Organization Admin, NOT Super Admin, and
// that gap is the single most important cell in the table. Super Admin is what
// turns row-level security off — it is the role that reads every tenant's data,
// not merely a bigger administrator — so a token that could name it would let
// anybody able to forge one walk out with the whole deployment. It is refused by
// the code below regardless of what this table, an override, or a ceiling says.
//
// L3 and L2 both land on Operator in either access mode, and that is a refusal
// to invent a role rather than an oversight. GuardRail seeds nothing between
// Operator (approval rank 10) and Organization Admin (50), so there is no
// "an L3 who can do slightly more" to promote into. A deployment that wants the
// distinction should create a role, give it a rank between the two, and point
// GUARDRAIL_SSO_ROLE_MAP at it — which is exactly what the override is for.
//
// read-only never maps to a role that can connect to a device. Auditor sees
// sessions, recordings and the audit trail and starts nothing; on a broker whose
// whole job is standing between people and privileged access, "read-only" has to
// mean it.
var defaultSSORoleTable = map[string]map[string]string{
	siemRoleAdministrator: {accessReadWrite: RoleOrgAdmin, accessReadOnly: RoleAuditor},
	siemRoleL3:            {accessReadWrite: RoleOperator, accessReadOnly: RoleAuditor},
	siemRoleL2:            {accessReadWrite: RoleOperator, accessReadOnly: RoleAuditor},
	siemRoleL1:            {accessReadWrite: RoleReadOnly, accessReadOnly: RoleReadOnly},
}

// SSORoleMap translates a SIEM role + access mode into a GuardRail role name.
type SSORoleMap struct {
	table map[string]map[string]string
	// def is the role a login with no recognised role claim resolves to.
	def string
}

// NewSSORoleMap builds the translation table, applying an optional JSON
// override.
//
// Malformed JSON falls back to the built-in table and reports the error for the
// caller to log loudly. It must not do either of the two obvious wrong things: a
// misconfiguration must not hand everybody an administrator's role, and it must
// not lock everybody out. Visible and harmless beats catastrophic in either
// direction, and the startup log names the fault.
//
// Two shapes are accepted:
//
//	{"L3": {"rw": "Senior Operator", "ro": "Auditor"},
//	 "L1": "Read-only"}
//
// the second being shorthand for "both access modes".
func NewSSORoleMap(overrideJSON, defaultRole string) (*SSORoleMap, error) {
	m := &SSORoleMap{table: cloneTable(defaultSSORoleTable), def: strings.TrimSpace(defaultRole)}
	if m.def == "" {
		m.def = RoleReadOnly
	}
	if strings.TrimSpace(overrideJSON) == "" {
		return m, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(overrideJSON), &raw); err != nil {
		return m, fmt.Errorf("iam: GUARDRAIL_SSO_ROLE_MAP is not valid JSON, using the built-in table: %w", err)
	}
	for key, val := range raw {
		role := normalizeSIEMRole(key)
		if role == "" {
			continue
		}
		var one string
		if err := json.Unmarshal(val, &one); err == nil {
			m.table[role] = map[string]string{accessReadWrite: one, accessReadOnly: one}
			continue
		}
		var pair map[string]string
		if err := json.Unmarshal(val, &pair); err != nil {
			return m, fmt.Errorf("iam: GUARDRAIL_SSO_ROLE_MAP entry %q is neither a role name nor {rw,ro}", key)
		}
		cell := m.table[role]
		if cell == nil {
			cell = map[string]string{}
		} else {
			cell = map[string]string{accessReadWrite: cell[accessReadWrite], accessReadOnly: cell[accessReadOnly]}
		}
		for k, v := range pair {
			if a := normalizeAccess(k); a != "" && strings.TrimSpace(v) != "" {
				cell[a] = strings.TrimSpace(v)
			}
		}
		m.table[role] = cell
	}
	return m, nil
}

// Resolve translates an asserted role and access mode.
//
// The second return says whether the ROLE was recognised, and callers depend on
// it for more than logging: a sync must not re-apply a role it did not
// understand, or a SIEM that stops sending the claim — a rename, a schema
// change, a bug on their side — would silently demote every SSO user to the
// default on their next sign-in.
//
// An absent or unrecognised access mode resolves to read-only. Between over- and
// under-granting on a claim nobody stated, only one of the two is safe.
func (m *SSORoleMap) Resolve(role, access string) (string, bool) {
	r := normalizeSIEMRole(role)
	cell, ok := m.table[r]
	if !ok {
		return m.def, false
	}
	a := normalizeAccess(access)
	if a == "" {
		a = accessReadOnly
	}
	name := cell[a]
	if strings.TrimSpace(name) == "" {
		// A half-configured override: the role is known, this access mode is not
		// mapped. Fall to the safer half of the row rather than to nothing.
		if fallback := cell[accessReadOnly]; strings.TrimSpace(fallback) != "" {
			return fallback, true
		}
		return m.def, false
	}
	return name, true
}

// Default is the role a login with no recognised role claim resolves to.
//
// Never "no roles at all", which is what GuardRail's OIDC and LDAP federation do
// and is right for them: those provision an account an administrator is expected
// to grant access to, and the person is told to wait. Here the SIEM is asserting
// that this person is an analyst right now, and a GuardRail account with no roles
// holds no permissions — it signs in successfully to a console where every page
// is empty and every action is refused, which reads as the product being broken
// rather than the person being unprivileged. Read-only is the floor that makes
// the sign-in mean something without granting anything.
func (m *SSORoleMap) Default() string { return m.def }

// Provenance renders what the SIEM asserted, for the audit trail and the
// sso_source_role column: "L3:ro". It answers "why does this person hold this
// role" without anybody having to reconstruct the mapping from memory.
func Provenance(role, access string) string {
	r := normalizeSIEMRole(role)
	if r == "" {
		r = "?"
	}
	a := normalizeAccess(access)
	if a == "" {
		a = accessReadOnly
	}
	return r + ":" + a
}

// normalizeSIEMRole folds the spellings an issuer might use onto one token.
//
// The SIEM may send L1, l1, "L1 Analyst", Tier-1 or LEVEL_1 and mean the same
// thing, and which one it sends can change with a UI relabel that nobody thought
// was an integration change. Strip every non-alphanumeric character, uppercase,
// then look up an alias table: a cosmetic change on the issuer's side must not
// silently drop everybody to the default role.
func normalizeSIEMRole(s string) string {
	k := squash(s)
	switch k {
	case "ADMINISTRATOR", "ADMIN", "SIEMADMIN", "SUPERADMIN", "ADMINISTRATORS":
		return siemRoleAdministrator
	case "L1", "L1ANALYST", "TIER1", "T1", "LEVEL1", "ANALYSTL1":
		return siemRoleL1
	case "L2", "L2ANALYST", "TIER2", "T2", "LEVEL2", "ANALYSTL2":
		return siemRoleL2
	case "L3", "L3ANALYST", "TIER3", "T3", "LEVEL3", "ANALYSTL3":
		return siemRoleL3
	default:
		return k
	}
}

// normalizeAccess folds access-mode spellings. Returns "" for anything it does
// not recognise, which callers read as "unstated" and treat as read-only.
func normalizeAccess(s string) string {
	switch squash(s) {
	case "RW", "READWRITE", "WRITE", "READANDWRITE", "FULL", "EDIT":
		return accessReadWrite
	case "RO", "READONLY", "READ", "VIEW", "VIEWONLY":
		return accessReadOnly
	default:
		return ""
	}
}

// squash uppercases and drops every non-alphanumeric character.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cloneTable(in map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(in))
	for k, v := range in {
		cell := make(map[string]string, len(v))
		for a, n := range v {
			cell[a] = n
		}
		out[k] = cell
	}
	return out
}
