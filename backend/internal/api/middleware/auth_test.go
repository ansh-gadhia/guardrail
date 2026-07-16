package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// stubAuth is a test Authenticator: it accepts the token "valid" and returns
// preset claims; anything else fails.
type stubAuth struct{ claims iam.Claims }

func (s stubAuth) Verify(token string) (iam.Claims, error) {
	if token == "valid" {
		return s.claims, nil
	}
	return iam.Claims{}, errors.New("invalid")
}

func protectedEngine(a Authenticator, perm string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", Authenticate(a), RequirePermission(perm), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func do(r *gin.Engine, bearer string) int {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestAuthenticate_MissingToken(t *testing.T) {
	r := protectedEngine(stubAuth{}, "device:read")
	if code := do(r, ""); code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", code)
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	r := protectedEngine(stubAuth{}, "device:read")
	if code := do(r, "garbage"); code != http.StatusUnauthorized {
		t.Fatalf("bad token = %d, want 401", code)
	}
}

func TestRBAC_GrantsWithPermission(t *testing.T) {
	a := stubAuth{claims: iam.Claims{Permissions: []string{"device:read"}}}
	r := protectedEngine(a, "device:read")
	if code := do(r, "valid"); code != http.StatusOK {
		t.Fatalf("with permission = %d, want 200", code)
	}
}

func TestRBAC_DeniesWithoutPermission(t *testing.T) {
	a := stubAuth{claims: iam.Claims{Permissions: []string{"session:read"}}}
	r := protectedEngine(a, "device:read")
	if code := do(r, "valid"); code != http.StatusForbidden {
		t.Fatalf("missing permission = %d, want 403", code)
	}
}

func TestRBAC_SuperAdminBypassesPermissionCheck(t *testing.T) {
	a := stubAuth{claims: iam.Claims{IsSuperAdmin: true}}
	r := protectedEngine(a, "device:read")
	if code := do(r, "valid"); code != http.StatusOK {
		t.Fatalf("super admin = %d, want 200", code)
	}
}
