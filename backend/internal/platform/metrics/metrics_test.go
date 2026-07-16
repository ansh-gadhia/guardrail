package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew_RegistersCollectors(t *testing.T) {
	r := New()
	if r.Prom == nil {
		t.Fatal("expected a prometheus registry")
	}
	// Go collector should expose at least one metric family.
	if n, err := testutil.GatherAndCount(r.Prom); err != nil || n == 0 {
		t.Fatalf("GatherAndCount = %d, err=%v; want >0", n, err)
	}
}

func TestMiddleware_RecordsRequest(t *testing.T) {
	reg := New()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(reg.Middleware())
	engine.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))

	got := testutil.CollectAndCount(reg.reqTotal)
	if got == 0 {
		t.Fatal("expected request counter to record at least one observation")
	}
}

func TestSetActiveSessions(t *testing.T) {
	reg := New()
	reg.SetActiveSessions(3)
	if v := testutil.ToFloat64(reg.activeSessions); v != 3 {
		t.Fatalf("active sessions gauge = %v, want 3", v)
	}
}
