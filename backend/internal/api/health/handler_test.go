package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type stubChecker struct{ err error }

func (s stubChecker) Health(context.Context) error { return s.err }

func newRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h.Routes(r)
	return r
}

func TestLiveness(t *testing.T) {
	r := newRouter(New("test"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", w.Code)
	}
}

func TestReadiness_AllHealthy(t *testing.T) {
	h := New("test").Register("db", stubChecker{}).Register("redis", stubChecker{})
	r := newRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", w.Code)
	}
}

func TestReadiness_DependencyDown(t *testing.T) {
	h := New("test").
		Register("db", stubChecker{}).
		Register("redis", stubChecker{err: errors.New("connection refused")})
	r := newRouter(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", w.Code)
	}
}
