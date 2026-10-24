package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// seededServer spins up an HTTP server backed by a freshly seeded store.
func seededServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := NewStore()
	if err := SeedAll(s); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := httptest.NewServer(NewServer(s).Handler())
	t.Cleanup(srv.Close)
	return srv
}

// response is a decoded HTTP outcome.
type response struct {
	status int
	body   map[string]any
	raw    string
}

// do issues a request with the given token and optional JSON body.
func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := response{status: res.StatusCode, raw: string(raw)}
	if len(raw) > 0 && json.Valid(raw) {
		_ = json.Unmarshal(raw, &out.body)
	}
	return out
}

// helper for a token.
func tok(user, tenant string) string { return TokenFor(user, tenant) }

// ---------- authentication -----------------------------------------------

func TestHealthIsPublic(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "GET", "/health", "", nil)
	if got.status != http.StatusOK {
		t.Errorf("health status = %d want 200", got.status)
	}
	// Health with no auth must NOT be 401.
	if got.status == http.StatusUnauthorized {
		t.Errorf("health should be public")
	}
}

func TestNoTokenIsUnauthorized(t *testing.T) {
	srv := seededServer(t)
	if got := do(t, srv, "GET", "/api/v1/products", "", nil); got.status != http.StatusUnauthorized {
		t.Errorf("missing token should 401, got %d", got.status)
	}
}

func TestInvalidTokenIsUnauthorized(t *testing.T) {
	srv := seededServer(t)
	if got := do(t, srv, "GET", "/api/v1/products", "garbage", nil); got.status != http.StatusUnauthorized {
		t.Errorf("unknown token should 401, got %d", got.status)
	}
}

func TestForgedIdentityHeadersAreIgnored(t *testing.T) {
	srv := seededServer(t)
	// A viewer cannot read customers. Add forged X-Role / X-User-Id headers —
	// they must have NO effect; identity comes only from the token.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/customers", nil)
	req.Header.Set("Authorization", "Bearer "+tok("u-acme-v", "acme"))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-User-Id", "u-acme-admin")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("forged headers must not elevate a viewer; got %d want 403", res.StatusCode)
	}
}

// ---------- matrix over HTTP ---------------------------------------------

func TestViewerCannotCreateProductOverHTTP(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "POST", "/api/v1/products", tok("u-acme-v", "acme"), map[string]any{"sku": "X", "name": "n"})
	if got.status != http.StatusForbidden {
		t.Errorf("viewer create product should be 403, got %d (%s)", got.status, got.raw)
	}
}

func TestManagerCannotDeleteProductOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// Manager has CRU on products but NOT D -> 403, and state must not change.
	admin := do(t, srv, "POST", "/api/v1/products", tok("u-acme-admin", "acme"), map[string]any{"sku": "DL", "name": "n"})
	if admin.status != http.StatusCreated {
		t.Fatalf("admin create product should be 201, got %d (%s)", admin.status, admin.raw)
	}
	id := asString(admin.body["id"])
	if id == "" {
		t.Fatalf("expected a created id, got %s", admin.raw)
	}
	// Manager delete -> 403.
	man := do(t, srv, "DELETE", "/api/v1/products/"+id, tok("u-acme-manager", "acme"), nil)
	if man.status != http.StatusForbidden {
		t.Errorf("manager delete product should be 403, got %d", man.status)
	}
	// The record must still exist (denied write left state unchanged).
	again := do(t, srv, "GET", "/api/v1/products/"+id, tok("u-acme-admin", "acme"), nil)
	if again.status != http.StatusOK {
		t.Errorf("product should still exist after a denied delete, got %d", again.status)
	}
}

func TestManagerCannotCreateCustomerOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// Customers: manager has RU only, so create must be 403.
	got := do(t, srv, "POST", "/api/v1/customers", tok("u-acme-manager", "acme"), map[string]any{"name": "x", "email": "a@b.com"})
	if got.status != http.StatusForbidden {
		t.Errorf("manager create customer should be 403, got %d (%s)", got.status, got.raw)
	}
}

func TestAdminCanCreateCustomerOverHTTP(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "POST", "/api/v1/customers", tok("u-acme-admin", "acme"), map[string]any{"name": "x", "email": "a@b.com"})
	if got.status != http.StatusCreated {
		t.Errorf("admin create customer should be 201, got %d (%s)", got.status, got.raw)
	}
}

func TestAuditLogsReadOnlyOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// No role may write audit logs.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		// Use a concrete id for put/patch/delete so the resource path is valid.
		path := "/api/v1/audit-logs"
		if m != "POST" {
			path = "/api/v1/audit-logs/audit-1"
		}
		got := do(t, srv, m, path, tok("u-acme-admin", "acme"), map[string]any{"x": 1})
		if got.status != http.StatusMethodNotAllowed {
			t.Errorf("admin %s audit-logs should be 405, got %d (%s)", m, got.status, got.raw)
		}
	}
	// Manager can read.
	if got := do(t, srv, "GET", "/api/v1/audit-logs", tok("u-acme-manager", "acme"), nil); got.status != http.StatusOK {
		t.Errorf("manager read audit-logs should be 200, got %d", got.status)
	}
	// Viewer cannot read.
	if got := do(t, srv, "GET", "/api/v1/audit-logs", tok("u-acme-v", "acme"), nil); got.status != http.StatusForbidden {
		t.Errorf("viewer read audit-logs should be 403, got %d", got.status)
	}
}

// ---------- ownership over HTTP ------------------------------------------

func TestViewerOwnOrdersOnlyOverHTTP(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "GET", "/api/v1/orders", tok("u-acme-v", "acme"), nil)
	if got.status != http.StatusOK {
		t.Fatalf("viewer list orders should be 200, got %d (%s)", got.status, got.raw)
	}
	items, ok := got.body["items"].([]any)
	if !ok {
		t.Fatalf("expected items array, got %s", got.raw)
	}
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["owner"] != "u-acme-v" {
			t.Errorf("viewer saw an order they do not own: owner=%v", m["owner"])
		}
	}
}

// ---------- tenant isolation over HTTP -----------------------------------

func TestCrossTenantObjectIsNotFoundOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// The u-multi user is a viewer in globex but admin in acme. Using the
	// globex token, an acme product id is not found (tenant isolation).
	acmeProduct := do(t, srv, "GET", "/api/v1/products/prod-1", tok("u-acme-admin", "acme"), nil)
	if acmeProduct.status != http.StatusOK {
		t.Fatalf("sanity: admin should read prod-1, got %d", acmeProduct.status)
	}
	// globex viewer trying acme data:
	got := do(t, srv, "GET", "/api/v1/products/prod-1", tok("u-multi", "globex"), nil)
	if got.status != http.StatusNotFound && got.status != http.StatusForbidden {
		t.Errorf("cross-tenant access should be 404/403, got %d (%s)", got.status, got.raw)
	}
}

// ---------- method not allowed / not found --------------------------------

func TestUnknownResourceIsNotFound(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "GET", "/api/v1/secret", tok("u-acme-admin", "acme"), nil)
	if got.status != http.StatusNotFound {
		t.Errorf("unknown resource should be 404, got %d", got.status)
	}
}

func TestUnknownObjectIsNotFound(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "GET", "/api/v1/products/nope-id", tok("u-acme-admin", "acme"), nil)
	if got.status != http.StatusNotFound {
		t.Errorf("unknown object should be 404, got %d", got.status)
	}
}

// ---------- member management over HTTP ----------------------------------

func TestMemberManagementIsAdminOnlyOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// Manager cannot add a member (and must not be able to promote anyone).
	got := do(t, srv, "POST", "/api/v1/members", tok("u-acme-manager", "acme"),
		map[string]any{"user": "bob", "role": "admin"})
	if got.status != http.StatusForbidden {
		t.Errorf("manager add member should be 403, got %d (%s)", got.status, got.raw)
	}
	// The promotion must not have happened.
	if check := do(t, srv, "GET", "/api/v1/members/bob", tok("u-acme-admin", "acme"), nil); check.status != http.StatusNotFound {
		t.Errorf("bob must not exist after a denied add, got %d (%s)", check.status, check.raw)
	}
}

func TestLastAdminProtectedOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// globex has exactly one admin: u-globex-admin.
	// Attempt to demote (last admin) -> 409.
	got := do(t, srv, "PATCH", "/api/v1/members/u-globex-admin", tok("u-globex-admin", "globex"),
		map[string]any{"role": "viewer"})
	if got.status != http.StatusConflict {
		t.Errorf("demoting last admin should be 409, got %d (%s)", got.status, got.raw)
	}
	// Attempt to remove (last admin) -> 409.
	del := do(t, srv, "DELETE", "/api/v1/members/u-globex-admin", tok("u-globex-admin", "globex"), nil)
	if del.status != http.StatusConflict {
		t.Errorf("removing last admin should be 409, got %d", del.status)
	}
	// Still present.
	if c := do(t, srv, "GET", "/api/v1/members/u-globex-admin", tok("u-globex-admin", "globex"), nil); c.status != http.StatusOK {
		t.Errorf("last admin should remain present, got %d (%s)", c.status, c.raw)
	}
}

func TestMembershipChangeTakesEffectOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// Admin promotes a brand-new user to admin, then that user can act.
	add := do(t, srv, "POST", "/api/v1/members", tok("u-acme-admin", "acme"),
		map[string]any{"user": "neo", "role": "admin"})
	if add.status != http.StatusCreated {
		t.Fatalf("admin add member should be 201, got %d (%s)", add.status, add.raw)
	}
	// The new token is deterministic: tok("neo","acme").
	// Before promotion the token is unknown (401); after, the member acts.
	// First, verify the token was minted: a create with it should be 201.
	c := do(t, srv, "POST", "/api/v1/products", tok("neo", "acme"), map[string]any{"sku": "NEO", "name": "n"})
	if c.status != http.StatusCreated {
		t.Errorf("newly added admin should be able to create, got %d (%s)", c.status, c.raw)
	}
	// Now revoke: admin sets neo to viewer.
	p := do(t, srv, "PATCH", "/api/v1/members/neo", tok("u-acme-admin", "acme"),
		map[string]any{"role": "viewer"})
	if p.status != http.StatusOK {
		t.Fatalf("promote/demote via PATCH should be 200, got %d (%s)", p.status, p.raw)
	}
	// neo is now a viewer -> cannot create.
	c2 := do(t, srv, "POST", "/api/v1/products", tok("neo", "acme"), map[string]any{"sku": "X", "name": "n"})
	if c2.status != http.StatusForbidden {
		t.Errorf("neo should be forbidden after demotion, got %d", c2.status)
	}
}

// ---------- validation ----------------------------------------------------

func TestInvalidJSONIsBadRequest(t *testing.T) {
	srv := seededServer(t)
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/products", strings.NewReader("not json"))
	req.Header.Set("Authorization", "Bearer "+tok("u-acme-admin", "acme"))
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid JSON should be 400, got %d", res.StatusCode)
	}
}

func TestInvalidLimitIsBadRequest(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "GET", "/api/v1/products?limit=abc", tok("u-acme-admin", "acme"), nil)
	if got.status != http.StatusBadRequest {
		t.Errorf("non-numeric limit should be 400, got %d", got.status)
	}
}

func TestInvalidEmailIsBadRequest(t *testing.T) {
	srv := seededServer(t)
	got := do(t, srv, "POST", "/api/v1/customers", tok("u-acme-admin", "acme"), map[string]any{"name": "x", "email": "nope"})
	if got.status != http.StatusBadRequest {
		t.Errorf("invalid email should be 400, got %d (%s)", got.status, got.raw)
	}
}

func TestMissingRequiredFieldIsBadRequest(t *testing.T) {
	srv := seededServer(t)
	// product requires sku + name.
	got := do(t, srv, "POST", "/api/v1/products", tok("u-acme-admin", "acme"), map[string]any{"name": "n"})
	if got.status != http.StatusBadRequest {
		t.Errorf("missing sku should be 400, got %d", got.status)
	}
}

// ---------- nested routes -------------------------------------------------

func TestNestedPaymentsOverHTTP(t *testing.T) {
	srv := seededServer(t)
	// Find an acme order owned by the viewer (so it exists) via admin list.
	list := do(t, srv, "GET", "/api/v1/orders", tok("u-acme-admin", "acme"), nil)
	items, _ := list.body["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("no orders seeded")
	}
	oid := asString(mapAny(items[0])["id"])
	// Manager can read nested payments.
	got := do(t, srv, "GET", "/api/v1/orders/"+oid+"/payments", tok("u-acme-manager", "acme"), nil)
	if got.status != http.StatusOK {
		t.Errorf("nested payments should be 200 for manager, got %d (%s)", got.status, got.raw)
	}
	// Viewer cannot read payments (None) -> 403 even nested.
	v := do(t, srv, "GET", "/api/v1/orders/"+oid+"/payments", tok("u-acme-v", "acme"), nil)
	if v.status != http.StatusForbidden {
		t.Errorf("nested payments should be 403 for viewer, got %d", v.status)
	}
}

// ---------- helpers -------------------------------------------------------

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func mapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
