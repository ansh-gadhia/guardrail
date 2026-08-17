package v1

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appvault "github.com/guardrail/guardrail/internal/app/vault"
	"github.com/guardrail/guardrail/internal/domain/iam"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
)

// Per-user accounts.
//
// These are named logins that exist ON THE TARGET DEVICE — `jsmith-admin` — not
// a person's own password. GuardRail must never hold somebody's personal
// directory credential, and the console labels the feature "per-user accounts"
// rather than "user credentials" precisely so nobody pastes the wrong thing in.

// accountBody is one binding, without secret material.
type accountBody struct {
	CredentialID string `json:"credential_id"`
	Name         string `json:"name"`
	Username     string `json:"username"`
	Injection    string `json:"injection"`
	UserID       string `json:"user_id,omitempty"`
	User         string `json:"user,omitempty"`
	// Scope is "device" or "group"; GroupName names the group when inherited.
	Scope     string `json:"scope"`
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	// AgeDays is how long the secret has gone unchanged, measured from the
	// rotation if there was one and from creation otherwise.
	AgeDays   int    `json:"age_days"`
	RotatedAt string `json:"rotated_at,omitempty"`
}

func accountView(b *appvault.BindingView) accountBody {
	out := accountBody{
		CredentialID: b.CredentialID.String(), Name: b.Name, Username: b.Username,
		Injection: string(b.Injection), User: b.UserEmail, AgeDays: b.AgeDays,
		Scope: "device",
	}
	if b.UserID != nil {
		out.UserID = b.UserID.String()
	}
	if b.GroupID != nil {
		out.Scope, out.GroupID, out.GroupName = "group", b.GroupID.String(), b.GroupName
	}
	if b.RotatedAt != nil {
		out.RotatedAt = b.RotatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// accountRequest is a per-user account write. Secret is write-only; leaving it
// empty on an existing account keeps the stored one, because the console never
// echoes a secret back to be re-sent.
type accountRequest struct {
	Username  string `json:"username"`
	Secret    string `json:"secret"`
	Injection string `json:"injection"`
	Name      string `json:"name"`
}

func (r accountRequest) toInput(meta appvault.ReqMeta, scheme string) appvault.CredentialInput {
	return appvault.CredentialInput{
		Name: r.Name, Username: r.Username,
		Injection: domvault.InjectionMethod(r.Injection),
		Scheme:    scheme, Secret: r.Secret, Meta: meta,
	}
}

func (h *AssetsHandler) listDeviceAccounts(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	own, inherited, err := h.vault.DeviceBindings(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	ownOut := make([]accountBody, 0, len(own))
	for i := range own {
		// The shared credential is not a per-user account; it has its own surface.
		if own[i].UserID == nil {
			continue
		}
		ownOut = append(ownOut, accountView(&own[i]))
	}
	inhOut := make([]accountBody, 0, len(inherited))
	for i := range inherited {
		inhOut = append(inhOut, accountView(&inherited[i]))
	}
	c.JSON(http.StatusOK, gin.H{"accounts": ownOut, "inherited": inhOut})
}

func (h *AssetsHandler) setDeviceAccount(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	deviceID, userID, ok := h.accountParams(c)
	if !ok {
		return
	}
	d, err := h.svc.GetDevice(c.Request.Context(), actor, deviceID)
	if err != nil {
		failAssets(c, err)
		return
	}
	var req accountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid account payload")
		return
	}
	if err := h.vault.SetForUser(c.Request.Context(), actor, &deviceID, nil, userID,
		req.toInput(vaultMeta(c), d.Scheme)); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetsHandler) clearDeviceAccount(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	deviceID, userID, ok := h.accountParams(c)
	if !ok {
		return
	}
	if err := h.vault.ClearForUser(c.Request.Context(), actor, &deviceID, nil, userID, vaultMeta(c)); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetsHandler) listGroupAccounts(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid group id")
		return
	}
	list, err := h.vault.GroupBindings(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	out := make([]accountBody, 0, len(list))
	for i := range list {
		out = append(out, accountView(&list[i]))
	}
	c.JSON(http.StatusOK, gin.H{"accounts": out})
}

func (h *AssetsHandler) setGroupAccount(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	groupID, userID, ok := h.accountParams(c)
	if !ok {
		return
	}
	var req accountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid account payload")
		return
	}
	// No scheme to validate against: a group holds devices of mixed protocols,
	// so the injection method is taken as given and checked per device when it
	// is actually used.
	if err := h.vault.SetForUser(c.Request.Context(), actor, nil, &groupID, userID,
		req.toInput(vaultMeta(c), "")); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetsHandler) clearGroupAccount(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	groupID, userID, ok := h.accountParams(c)
	if !ok {
		return
	}
	if err := h.vault.ClearForUser(c.Request.Context(), actor, nil, &groupID, userID, vaultMeta(c)); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// accountParams parses the :id and :userID path parameters.
func (h *AssetsHandler) accountParams(c *gin.Context) (parent, userID uuid.UUID, ok bool) {
	parent, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid id")
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = uuid.Parse(c.Param("userID"))
	if err != nil {
		badRequest(c, "invalid user id")
		return uuid.Nil, uuid.Nil, false
	}
	return parent, userID, true
}

// deviceWhoAmI answers "which account will I connect as", before the click.
//
// It removes an entire class of confusion: on a shared device you are the
// device's own login, on a per-user device you are your named account, and on a
// per-user device with nothing bound for you the connect is going to be refused
// — which is much better learned here than at Connect.
func (h *AssetsHandler) deviceWhoAmI(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	d, err := h.svc.GetDevice(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	cred, err := h.vault.GetForDevice(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	body := gin.H{
		"credential_mode": d.CredentialMode,
		"allow_unmanaged": d.AllowUnmanaged,
		"has_credential":  cred != nil,
	}
	if cred != nil {
		body["username"] = cred.Username
		body["per_user"] = cred.PerUser
		body["inherited"] = cred.Inherited
		body["age_days"] = cred.AgeDays
	}
	c.JSON(http.StatusOK, body)
}

func (h *AssetsHandler) listUserAccounts(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	userID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	list, err := h.vault.UserBindings(c.Request.Context(), actor, userID)
	if err != nil {
		failAssets(c, err)
		return
	}
	out := make([]accountBody, 0, len(list))
	for i := range list {
		out = append(out, accountView(&list[i]))
	}
	c.JSON(http.StatusOK, gin.H{"accounts": out})
}

// retireUserAccounts soft-deletes every account belonging to one person, for
// offboarding. Explicit rather than a database cascade: a deletion that quietly
// destroys vault material is its own incident, and the count comes back so
// somebody can see what just happened.
func (h *AssetsHandler) retireUserAccounts(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	userID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	n, err := h.vault.RetireUserCredentials(c.Request.Context(), actor, userID, vaultMeta(c))
	if err != nil {
		failAssets(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"retired": n})
}

// staleCredentials lists secrets that have gone unchanged for too long.
//
// Per-user accounts multiply the number of secrets in the vault by the number
// of people, and stale ones are how that rots — so the age is surfaced rather
// than left to be discovered.
func (h *AssetsHandler) staleCredentials(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	// Plain days. This parsed the value as hours and then multiplied by 24 again,
	// so the console's "180 days" asked for 4320 — and the panel reported nothing
	// overdue no matter how old the vault got, which is the worst way for a
	// hygiene surface to fail: silently, and reassuringly.
	days := 90
	if v := c.Query("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	list, err := h.vault.StaleCredentials(c.Request.Context(), actor,
		time.Duration(days)*24*time.Hour, queryLimit(c))
	if err != nil {
		failAssets(c, err)
		return
	}
	out := make([]gin.H, 0, len(list))
	for i := range list {
		v := &list[i]
		row := gin.H{"id": v.ID.String(), "name": v.Name, "username": v.Username, "age_days": v.AgeDays}
		if v.RotatedAt != nil {
			row["rotated_at"] = v.RotatedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, gin.H{"credentials": out, "older_than_days": days})
}

// importAccountRow is one line of a bulk import.
type importAccountRow struct {
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	DeviceID  string `json:"device_id"`
	GroupID   string `json:"group_id"`
	Username  string `json:"username"`
	Secret    string `json:"secret"`
	Injection string `json:"injection"`
	Name      string `json:"name"`
}

// importAccounts binds per-user accounts in bulk.
//
// Forty people across twenty devices is not a form-fill job, and without this
// the feature stops being usable at about the size where it starts being worth
// having. Rows are applied independently and every failure is reported with its
// index, so one bad line does not discard the other thirty-nine.
func (h *AssetsHandler) importAccounts(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var body struct {
		Accounts []importAccountRow `json:"accounts" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		badRequest(c, "expected an accounts array")
		return
	}
	if len(body.Accounts) == 0 {
		badRequest(c, "no accounts to import")
		return
	}
	if len(body.Accounts) > 500 {
		badRequest(c, "import at most 500 accounts at a time")
		return
	}

	type rowErr struct {
		Index int    `json:"index"`
		Error string `json:"error"`
	}
	idx, err := h.buildUserIndex(c, actor)
	if err != nil {
		failAssets(c, err)
		return
	}

	imported := 0
	failures := make([]rowErr, 0)
	for i := range body.Accounts {
		row := &body.Accounts[i]
		userID, err := idx.resolve(row)
		if err != nil {
			failures = append(failures, rowErr{Index: i, Error: err.Error()})
			continue
		}
		var deviceID, groupID *uuid.UUID
		scheme := ""
		switch {
		case row.DeviceID != "":
			id, perr := uuid.Parse(row.DeviceID)
			if perr != nil {
				failures = append(failures, rowErr{Index: i, Error: "invalid device_id"})
				continue
			}
			d, derr := h.svc.GetDevice(c.Request.Context(), actor, id)
			if derr != nil {
				failures = append(failures, rowErr{Index: i, Error: "device not found"})
				continue
			}
			scheme = d.Scheme
			deviceID = &id
		case row.GroupID != "":
			id, perr := uuid.Parse(row.GroupID)
			if perr != nil {
				failures = append(failures, rowErr{Index: i, Error: "invalid group_id"})
				continue
			}
			groupID = &id
		default:
			failures = append(failures, rowErr{Index: i, Error: "needs a device_id or a group_id"})
			continue
		}
		if row.Secret == "" {
			failures = append(failures, rowErr{Index: i, Error: "secret is required"})
			continue
		}
		in := accountRequest{
			Username: row.Username, Secret: row.Secret,
			Injection: row.Injection, Name: row.Name,
		}.toInput(vaultMeta(c), scheme)
		if serr := h.vault.SetForUser(c.Request.Context(), actor, deviceID, groupID, userID, in); serr != nil {
			failures = append(failures, rowErr{Index: i, Error: serr.Error()})
			continue
		}
		imported++
	}
	c.JSON(http.StatusOK, gin.H{"imported": imported, "failed": failures})
}

// userIndex maps lowercased email -> id for a bulk import.
//
// Built ONCE per import rather than per row: resolving inside the loop meant a
// 500-row CSV issued 500 full user listings, and each of those is a scoped
// query. Truncated reports whether the tenant has more users than one page
// returns, so an unmatched email can say which of the two things went wrong.
type userIndex struct {
	byEmail   map[string]uuid.UUID
	truncated bool
}

func (h *AssetsHandler) buildUserIndex(c *gin.Context, actor iam.Claims) (userIndex, error) {
	idx := userIndex{byEmail: map[string]uuid.UUID{}}
	if h.users == nil {
		return idx, nil
	}
	// The repository caps a page at 200 and honours no cursor, so this is
	// everything one call can see. Rather than silently resolving the first 200
	// people and telling everybody else they do not exist, record the cap and
	// say so on the rows it actually affects.
	people, err := h.users.ListUsers(c.Request.Context(), actor, iam.Page{Limit: userPageCap})
	if err != nil {
		return idx, err
	}
	for i := range people {
		idx.byEmail[strings.ToLower(strings.TrimSpace(people[i].Email))] = people[i].UserID
	}
	idx.truncated = len(people) >= userPageCap
	return idx, nil
}

// userPageCap mirrors the repository's page ceiling.
const userPageCap = 200

// resolve turns an import row's user_id or user_email into a user id.
func (idx userIndex) resolve(row *importAccountRow) (uuid.UUID, error) {
	if row.UserID != "" {
		id, err := uuid.Parse(row.UserID)
		if err != nil {
			return uuid.Nil, errInvalidUser
		}
		return id, nil
	}
	if row.UserEmail == "" {
		return uuid.Nil, errInvalidUser
	}
	if id, ok := idx.byEmail[strings.ToLower(strings.TrimSpace(row.UserEmail))]; ok {
		return id, nil
	}
	if idx.truncated {
		return uuid.Nil, errLookupTruncated
	}
	return uuid.Nil, errNoSuchUser
}

var (
	errInvalidUser     = errors.New("needs a user_id or a user_email")
	errNoSuchUser      = errors.New("no user with that email")
	errLookupTruncated = errors.New(
		"email lookup only covers the first 200 users and this address was not among them; supply user_id for this row")
)
