package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rbac/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st := store.New()
	srv := NewServer(st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func do(t *testing.T, ts *httptest.Server, method, path, token string, body any) (*http.Response, string) {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequest(method, ts.URL+path, buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, raw.String()
}

func adminToken() string   { return "acme:admin" }
func managerToken() string { return "acme:emma" }
func viewerToken() string  { return "acme:liam" }

func TestMissingTokenReturns401(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/products", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestInvalidTokenReturns401(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/products", "bogus-token", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSpoofedBasicAuthRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/products", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for basic auth, got %d", resp.StatusCode)
	}
}

func TestViewerCannotCreateProduct(t *testing.T) {
	ts, st := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/products", viewerToken(), map[string]any{"sku": "X-1", "name": "Forbidden", "price": 5})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	products, _, err := st.ListProducts("acme", "", 100, 0)
	if err != nil {
		t.Fatalf("list products: %v", err)
	}
	if len(products) != 2 {
		t.Fatalf("expected product count unchanged, got %d", len(products))
	}
}

func TestAdminCanCreateAndReadProduct(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/products", adminToken(), map[string]any{"sku": "X-1", "name": "Widget", "price": 9.99})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	resp2, _ := do(t, ts, http.MethodGet, "/v1/products/prd_acme_3", adminToken(), nil)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestViewerSeesOnlyOwnOrders(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, bodyStr := do(t, ts, http.MethodGet, "/v1/orders", viewerToken(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var envelope struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(bodyStr), &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if envelope.Total != 1 || len(envelope.Data) != 1 {
		t.Fatalf("expected viewer to see only own order, got total=%d len=%d", envelope.Total, len(envelope.Data))
	}
	if envelope.Data[0].ID != "ord_acme_1" {
		t.Fatalf("expected own order ord_acme_1, got %s", envelope.Data[0].ID)
	}
}

func TestCrossTenantAccessDenied(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/products/prd_acme_1", "globex:admin", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 cross tenant, got %d", resp.StatusCode)
	}
}

func TestLastAdminProtection(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPut, "/v1/members/admin", adminToken(), map[string]any{"role": "viewer"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 last_admin, got %d", resp.StatusCode)
	}
	resp2, _ := do(t, ts, http.MethodDelete, "/v1/members/admin", adminToken(), nil)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 last_admin on delete, got %d", resp2.StatusCode)
	}
}

func TestAdminCannotPromoteWithoutPermission(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPut, "/v1/members/liam", managerToken(), map[string]any{"role": "admin"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestRouteNotFound(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/does-not-exist", adminToken(), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAdminCanCreateOrder(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/orders", adminToken(), map[string]any{
		"customerId": "liam",
		"items":      []map[string]any{{"productId": "prd_acme_1", "quantity": 2, "unitPrice": 25.99}},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestViewerCannotCreateOrder(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/orders", viewerToken(), map[string]any{
		"customerId": "liam",
		"items":      []map[string]any{{"productId": "prd_acme_1", "quantity": 1, "unitPrice": 25.99}},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestAdminCannotCreatePriceForUnknownProduct(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/prices", adminToken(), map[string]any{"productId": "prd_missing", "amount": 5})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPaymentsDeniedForViewer(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/payments", viewerToken(), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestAdminKeyCreateForbiddenForManager(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodPost, "/v1/api-keys", managerToken(), map[string]any{"name": "ops"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestAuditLogAccess(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, _ := do(t, ts, http.MethodGet, "/v1/audit-logs", viewerToken(), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer, got %d", resp.StatusCode)
	}
	resp2, _ := do(t, ts, http.MethodGet, "/v1/audit-logs", adminToken(), nil)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for admin, got %d", resp2.StatusCode)
	}
}
