package rbac_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"rbac/internal/rbac"
)

const base = "/tenants/tenant-a/"

type testAPI struct {
	handler http.Handler
	tokens  map[string]string
}

func newAPI(t *testing.T) *testAPI {
	t.Helper()
	handler, err := rbac.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("fixtures/seed.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Users []struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		} `json:"users"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	a := &testAPI{handler: handler, tokens: make(map[string]string)}
	for _, user := range fixture.Users {
		a.tokens[user.ID] = user.Token
	}
	return a
}

func (a *testAPI) raw(user, method, path, body string, headers ...map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if user != "" {
		request.Header.Set("Authorization", "Bearer "+a.tokens[user])
	}
	if method == "POST" || method == "PATCH" || method == "PUT" {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, extra := range headers {
		for key, value := range extra {
			request.Header.Set(key, value)
		}
	}
	response := httptest.NewRecorder()
	a.handler.ServeHTTP(response, request)
	return response
}

func (a *testAPI) call(t *testing.T, user, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		data = string(encoded)
	}
	return a.raw(user, method, path, data)
}

func expect(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, status, response.Body.String())
	}
}

func object(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("invalid JSON response: %v; body: %s", err, response.Body.String())
	}
	return value
}

func rows(t *testing.T, response *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	value := object(t, response)
	data, ok := value["data"].([]any)
	if !ok {
		t.Fatalf("list data must be an array: %v", value)
	}
	result := make([]map[string]any, 0, len(data))
	for _, item := range data {
		result = append(result, item.(map[string]any))
	}
	return result
}

type resourceCase struct {
	name   string
	id     string
	create map[string]any
	patch  map[string]any
	// C, R, U, D; these expectations deliberately do not import the policy.
	manager string
	viewer  string
}

func resourceCases() []resourceCase {
	return []resourceCase{
		{"products", "product-a-1", map[string]any{"name": "New product", "description": "Details", "sku": "NEW", "active": false}, map[string]any{"name": "Updated product"}, "CRU", "R"},
		{"prices", "price-a-1", map[string]any{"product_id": "product-a-1", "amount": 500, "currency": "USD"}, map[string]any{"amount": 600}, "RU", "R"},
		{"orders", "order-a-viewer", map[string]any{"customer_id": "customer-a-1", "total": 500, "currency": "USD"}, map[string]any{"status": "paid"}, "CRU", "R"},
		{"customers", "customer-a-1", map[string]any{"name": "New customer", "email": "new@example.com"}, map[string]any{"name": "Updated customer"}, "RU", ""},
		{"invoices", "invoice-a-viewer", map[string]any{"order_id": "order-a-viewer", "amount": 500, "currency": "USD"}, map[string]any{"status": "paid"}, "CR", "R"},
		{"payments", "payment-a-1", map[string]any{"order_id": "order-a-viewer", "invoice_id": "invoice-a-viewer", "amount": 500, "currency": "USD"}, map[string]any{"status": "failed"}, "R", ""},
		{"refunds", "refund-a-1", map[string]any{"payment_id": "payment-a-1", "amount": 100, "reason": "Test"}, map[string]any{"reason": "Updated reason"}, "CR", ""},
		{"inventory", "inventory-a-1", map[string]any{"product_id": "product-a-1", "quantity": 5}, map[string]any{"quantity": 8}, "RU", "R"},
		{"api-keys", "api-key-a-1", map[string]any{"name": "New key", "scopes": []string{"products:read"}}, map[string]any{"enabled": false}, "", ""},
		{"audit-logs", "audit-log-a-1", map[string]any{"action": "create"}, map[string]any{"action": "forged"}, "R", ""},
	}
}

func TestHTTPPermissionMatrix(t *testing.T) {
	operations := []struct {
		name, method, permission string
		status                   int
	}{
		{"list", "GET", "R", 200}, {"read", "GET", "R", 200},
		{"create", "POST", "C", 201}, {"patch", "PATCH", "U", 200},
		{"put", "PUT", "U", 200}, {"delete", "DELETE", "D", 204},
	}
	for _, resource := range resourceCases() {
		t.Run(resource.name, func(t *testing.T) {
			for _, role := range []string{"admin", "manager", "viewer"} {
				t.Run(role, func(t *testing.T) {
					for _, op := range operations {
						t.Run(op.name, func(t *testing.T) {
							a := newAPI(t)
							grants := "CRUD"
							if role == "manager" {
								grants = resource.manager
							} else if role == "viewer" {
								grants = resource.viewer
							} else if resource.name == "audit-logs" {
								grants = "R"
							}
							path := base + resource.name
							var body any
							id := resource.id
							if op.name == "delete" && resource.name != "audit-logs" {
								created := a.call(t, "user-admin", "POST", path, resource.create)
								expect(t, created, 201)
								id = object(t, created)["id"].(string)
							}
							if op.name != "list" && op.name != "create" {
								path += "/" + id
							}
							if op.name == "create" || op.name == "put" {
								body = resource.create
							} else if op.name == "patch" {
								body = resource.patch
							}
							status := op.status
							if !strings.Contains(grants, op.permission) {
								status = 403
							}
							result := a.call(t, "user-"+role, op.method, path, body)
							expect(t, result, status)
							if status == 201 && result.Header().Get("Location") == "" {
								t.Error("created record has no Location header")
							}
							if status == 204 {
								if result.Body.Len() != 0 {
									t.Error("DELETE response must have an empty body")
								}
								expect(t, a.call(t, "user-admin", "GET", path, nil), 404)
							}
						})
					}
				})
			}
		})
	}
}

func TestAuthenticationAndSpoofing(t *testing.T) {
	a := newAPI(t)
	for name, authorization := range map[string]string{
		"missing": "", "basic": "Basic abc", "empty-bearer": "Bearer", "unknown": "Bearer forged-token",
		"extra-fields":            "Bearer " + a.tokens["user-admin"] + " extra",
		"identity-is-not-a-token": "Bearer user-admin", "role-is-not-a-token": "Bearer admin",
		"api-key-is-not-a-token": "Bearer ak_fixture_a_G2pRw8Qk7xN3sL6mV9cTa0bHd5eYj1UF",
	} {
		t.Run(name, func(t *testing.T) {
			result := a.raw("", "GET", base+"products", "", map[string]string{
				"Authorization": authorization, "X-User-ID": "user-admin", "X-Role": "admin", "X-Tenant-ID": "tenant-a",
			})
			expect(t, result, 401)
			if result.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 response has no authentication challenge")
			}
		})
	}
	request := httptest.NewRequest("GET", base+"products", nil)
	request.Header.Add("Authorization", "Bearer "+a.tokens["user-viewer"])
	request.Header.Add("Authorization", "Bearer "+a.tokens["user-admin"])
	result := httptest.NewRecorder()
	a.handler.ServeHTTP(result, request)
	expect(t, result, 401)
	expect(t, a.raw("", "GET", base+"products", "", map[string]string{"Authorization": "bearer " + a.tokens["user-viewer"]}), 200)
	for _, path := range []string{base + "products", base + "products?role=admin&user_id=user-admin&tenant_id=tenant-b"} {
		expect(t, a.raw("user-viewer", "POST", path, `{"name":"Forged","role":"admin","user_id":"user-admin"}`, map[string]string{
			"X-Role": "admin", "X-User-ID": "user-admin", "X-Tenant-ID": "tenant-b",
		}), 403)
	}
	expect(t, a.call(t, "user-outsider", "GET", base+"products", nil), 403)
	expect(t, a.call(t, "user-admin-2", "GET", base+"products", nil), 403)
}

func TestTenantIsolation(t *testing.T) {
	a := newAPI(t)
	for _, resource := range resourceCases() {
		t.Run(resource.name, func(t *testing.T) {
			foreignID := strings.Replace(resource.id, "-a-", "-b-", 1)
			if resource.name == "orders" || resource.name == "invoices" {
				foreignID = resource.name[:len(resource.name)-1] + "-b-admin"
			}
			path := base + resource.name + "/" + foreignID
			expect(t, a.call(t, "user-admin", "GET", path, nil), 404)
			if resource.name != "audit-logs" {
				expect(t, a.call(t, "user-admin", "PATCH", path, resource.patch), 404)
				expect(t, a.call(t, "user-admin", "DELETE", path, nil), 404)
			}
			result := a.call(t, "user-admin", "GET", base+resource.name+"?limit=100", nil)
			expect(t, result, 200)
			for _, item := range rows(t, result) {
				if item["tenant_id"] != "tenant-a" {
					t.Fatalf("cross-tenant record leaked: %v", item)
				}
			}
		})
	}
	// The same token is an administrator in A and a viewer in B.
	expect(t, a.call(t, "user-admin", "POST", "/tenants/tenant-b/products", map[string]any{"name": "Denied"}), 403)
	expect(t, a.call(t, "user-manager", "POST", "/tenants/tenant-b/customers", map[string]any{"name": "Allowed", "email": "allowed@example.com"}), 201)
	expect(t, a.call(t, "user-admin", "GET", "/tenants/missing/products", nil), 404)
	expect(t, a.call(t, "user-admin", "GET", base+"orders/order-b-admin/invoices", nil), 404)
	expect(t, a.call(t, "user-admin", "POST", base+"prices", map[string]any{"product_id": "product-b-1", "amount": 1, "currency": "USD"}), 404)
	expect(t, a.call(t, "user-manager", "POST", base+"invoices", map[string]any{"order_id": "order-b-admin", "amount": 1, "currency": "USD"}), 404)
}

func TestViewerOwnershipAndFiltering(t *testing.T) {
	a := newAPI(t)
	for _, resource := range []string{"orders", "invoices"} {
		t.Run(resource, func(t *testing.T) {
			prefix := strings.TrimSuffix(resource, "s")
			expect(t, a.call(t, "user-viewer", "GET", base+resource+"/"+prefix+"-a-viewer", nil), 200)
			expect(t, a.call(t, "user-viewer", "GET", base+resource+"/"+prefix+"-a-other", nil), 404)
			result := a.call(t, "user-viewer", "GET", base+resource+"?limit=100", nil)
			expect(t, result, 200)
			items := rows(t, result)
			if len(items) != 1 || items[0]["owner_id"] != "user-viewer" || object(t, result)["total"] != float64(1) {
				t.Fatalf("ownership filter or total leaked records: %s", result.Body.String())
			}
			filtered := a.call(t, "user-viewer", "GET", base+resource+"?owner_id=user-viewer-2", nil)
			expect(t, filtered, 200)
			if len(rows(t, filtered)) != 0 || object(t, filtered)["total"] != float64(0) {
				t.Fatal("owner_id filter bypassed ownership")
			}
			staff := a.call(t, "user-manager", "GET", base+resource+"?owner_id=user-viewer-2", nil)
			expect(t, staff, 200)
			if len(rows(t, staff)) != 1 {
				t.Fatal("manager could not read another user's record")
			}
		})
	}
	expect(t, a.call(t, "user-viewer", "GET", base+"orders/order-a-other/invoices", nil), 404)
	result := a.call(t, "user-viewer", "GET", base+"orders/order-a-viewer/invoices", nil)
	expect(t, result, 200)
	if len(rows(t, result)) != 1 {
		t.Fatal("own nested invoices are missing")
	}
	expect(t, a.call(t, "user-viewer", "GET", base+"orders/order-a-viewer/payments", nil), 403)
	// Being the customer of an order never grants access to the customer route.
	expect(t, a.call(t, "user-viewer", "GET", base+"customers/customer-a-1/orders", nil), 404)
	expect(t, a.call(t, "user-admin", "GET", "/tenants/tenant-b/orders/order-b-admin", nil), 200)
	expect(t, a.call(t, "user-admin", "GET", "/tenants/tenant-b/orders/order-b-other", nil), 404)
}

func TestServerAssignedOwnership(t *testing.T) {
	a := newAPI(t)
	created := a.call(t, "user-manager", "POST", base+"orders", map[string]any{"customer_id": "customer-a-1", "total": 100, "currency": "USD"})
	expect(t, created, 201)
	order := object(t, created)
	if order["owner_id"] != "user-manager" {
		t.Fatalf("order owner was not assigned from token: %v", order)
	}
	created = a.call(t, "user-manager", "POST", base+"orders/order-a-viewer/invoices", map[string]any{"amount": 100, "currency": "USD"})
	expect(t, created, 201)
	invoice := object(t, created)
	if invoice["owner_id"] != "user-viewer" || invoice["order_id"] != "order-a-viewer" {
		t.Fatalf("invoice did not inherit its order's owner: %v", invoice)
	}
	expect(t, a.call(t, "user-viewer", "GET", base+"invoices/"+invoice["id"].(string), nil), 200)
	for _, field := range []string{"owner_id", "user_id", "tenant_id", "id", "role"} {
		payload := map[string]any{"customer_id": "customer-a-1", "total": 100, "currency": "USD", field: "user-viewer"}
		expect(t, a.call(t, "user-manager", "POST", base+"orders", payload), 400)
	}
	expect(t, a.call(t, "user-admin", "PATCH", base+"orders/order-a-viewer", map[string]any{"owner_id": "user-admin"}), 400)
	expect(t, a.call(t, "user-admin", "PATCH", base+"invoices/invoice-a-viewer", map[string]any{"order_id": "order-a-other"}), 409)
}

// Snapshots use public admin routes and include audit logs, so failed mutations
// must leave both commerce data and membership history unchanged.
func snapshot(t *testing.T, a *testAPI) string {
	t.Helper()
	state := make(map[string]any)
	for _, tenant := range []struct{ id, user string }{{"tenant-a", "user-admin"}, {"tenant-b", "user-manager"}} {
		for _, resource := range append(resourceCases(), resourceCase{name: "members"}) {
			path := "/tenants/" + tenant.id + "/" + resource.name + "?limit=100"
			result := a.call(t, tenant.user, "GET", path, nil)
			expect(t, result, 200)
			state[tenant.id+"/"+resource.name] = object(t, result)
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDeniedWritesLeaveStateUnchanged(t *testing.T) {
	a := newAPI(t)
	before := snapshot(t, a)
	for _, resource := range resourceCases() {
		for _, user := range []string{"user-viewer", "user-manager"} {
			grants := resource.viewer
			if user == "user-manager" {
				grants = resource.manager
			}
			for _, operation := range []struct{ method, permission string }{{"POST", "C"}, {"PATCH", "U"}, {"PUT", "U"}, {"DELETE", "D"}} {
				if strings.Contains(grants, operation.permission) {
					continue
				}
				path := base + resource.name
				body := resource.create
				if operation.method != "POST" {
					path += "/" + resource.id
					if operation.method == "PATCH" {
						body = resource.patch
					}
				}
				expect(t, a.call(t, user, operation.method, path, body), 403)
			}
		}
	}
	if after := snapshot(t, a); before != after {
		t.Fatal("a denied write changed a record, membership, or audit log")
	}
}

func TestListPaginationSortingAndValidation(t *testing.T) {
	a := newAPI(t)
	first := a.call(t, "user-viewer", "GET", base+"products?limit=1&offset=0&sort=id&order=asc", nil)
	second := a.call(t, "user-viewer", "GET", base+"products?limit=1&offset=1", nil)
	expect(t, first, 200)
	expect(t, second, 200)
	if len(rows(t, first)) != 1 || len(rows(t, second)) != 1 || object(t, first)["total"] != float64(2) {
		t.Fatal("pagination or total is incorrect")
	}
	if rows(t, first)[0]["id"] != "product-a-1" || rows(t, second)[0]["id"] != "product-a-2" {
		t.Fatal("pagination is not deterministic")
	}
	desc := a.call(t, "user-viewer", "GET", base+"products?order=desc", nil)
	expect(t, desc, 200)
	if rows(t, desc)[0]["id"] != "product-a-2" {
		t.Fatal("descending sorting failed")
	}
	filtered := a.call(t, "user-viewer", "GET", base+"products?sku=MUG-A&active=true", nil)
	expect(t, filtered, 200)
	if len(rows(t, filtered)) != 1 || rows(t, filtered)[0]["id"] != "product-a-2" {
		t.Fatal("combined equality filters failed")
	}
	empty := a.call(t, "user-viewer", "GET", base+"products?offset=9223372036854775807", nil)
	expect(t, empty, 200)
	if len(rows(t, empty)) != 0 || object(t, empty)["total"] != float64(2) {
		t.Fatal("out-of-range page is incorrect")
	}
	for _, query := range []string{"limit=0", "limit=101", "limit=no", "offset=-1", "offset=999999999999999999999999", "sort=name", "order=sideways", "unknown=1", "limit=1&limit=2", "role=admin", "tenant_id=tenant-b", "sku=%zz"} {
		t.Run(query, func(t *testing.T) {
			expect(t, a.call(t, "user-viewer", "GET", base+"products?"+query, nil), 400)
		})
	}
	memberList := a.call(t, "user-admin", "GET", base+"members?role=viewer&sort=user_id&limit=1&offset=1", nil)
	expect(t, memberList, 200)
	if len(rows(t, memberList)) != 1 || rows(t, memberList)[0]["user_id"] != "user-viewer-2" || object(t, memberList)["total"] != float64(2) {
		t.Fatal("member filtering or pagination is incorrect")
	}
}

func TestHTTPMethodsRoutesAndHealth(t *testing.T) {
	a := newAPI(t)
	health := a.call(t, "", "GET", "/health", nil)
	expect(t, health, 200)
	if object(t, health)["status"] != "ok" {
		t.Fatal("invalid health response")
	}
	for _, item := range []struct{ method, path, allow string }{
		{"DELETE", base + "products", "GET, POST"}, {"PUT", base + "members", "GET, POST"},
		{"POST", base + "products/product-a-1", "GET, PUT, PATCH, DELETE"},
		{"OPTIONS", base + "orders", "GET, POST"}, {"POST", "/health", "GET"},
	} {
		result := a.call(t, "user-admin", item.method, item.path, map[string]any{"name": "No change"})
		expect(t, result, 405)
		if result.Header().Get("Allow") != item.allow {
			t.Errorf("Allow = %q, want %q", result.Header().Get("Allow"), item.allow)
		}
	}
	for _, path := range []string{"/", "/tenants", "/tenants/tenant-a", base + "unknown", base + "api_keys", base + "audit_logs", base + "products//prices", base + "products/../prices", base + "products/product-a-1/orders", base + "members/user-admin/products", base + "products/product-a-1%2Fprices"} {
		expect(t, a.call(t, "user-admin", "GET", path, nil), 404)
	}
	expect(t, a.call(t, "user-admin", "GET", base+"products/", nil), 200)
	expect(t, a.call(t, "", "PATCH", base+"products/product-a-1", nil), 401)
}

func TestAPIKeysAndAuditAreProtected(t *testing.T) {
	a := newAPI(t)
	created := a.call(t, "user-admin", "POST", base+"api-keys", map[string]any{"name": "Integration"})
	expect(t, created, 201)
	key := object(t, created)
	if value, ok := key["key"].(string); !ok || len(value) < 32 {
		t.Fatal("API key was not generated")
	}
	path := base + "api-keys/" + key["id"].(string)
	expect(t, a.call(t, "user-manager", "GET", path, nil), 403)
	expect(t, a.call(t, "user-viewer", "GET", path, nil), 403)
	expect(t, a.raw("", "GET", base+"products", "", map[string]string{"Authorization": "Bearer " + key["key"].(string)}), 401)
	updated := a.call(t, "user-admin", "PUT", path, map[string]any{"name": "Renamed", "scopes": []string{"orders:read"}})
	expect(t, updated, 200)
	if object(t, updated)["key"] != key["key"] {
		t.Fatal("PUT changed a server-generated API key")
	}
	entries := a.call(t, "user-manager", "GET", base+"audit-logs?resource=api-keys&limit=100", nil)
	expect(t, entries, 200)
	if len(rows(t, entries)) != 2 {
		t.Fatalf("successful writes were not audited: %s", entries.Body.String())
	}
	if strings.Contains(entries.Body.String(), key["key"].(string)) {
		t.Fatal("audit log contains an API secret")
	}
	for _, user := range []string{"user-admin", "user-manager", "user-viewer"} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			path := base + "audit-logs"
			if method != "POST" {
				path += "/audit-log-a-1"
			}
			expect(t, a.call(t, user, method, path, map[string]any{"action": "forged"}), 403)
		}
	}
}

func TestIndependentServers(t *testing.T) {
	a, b := newAPI(t), newAPI(t)
	expect(t, a.call(t, "user-admin", "PATCH", base+"products/product-a-1", map[string]any{"name": "Changed"}), 200)
	result := b.call(t, "user-admin", "GET", base+"products/product-a-1", nil)
	expect(t, result, 200)
	if object(t, result)["name"] != "Coffee A" {
		t.Fatal("separate API instances share mutable fixture data")
	}
}

func TestConcurrentCRUD(t *testing.T) {
	a := newAPI(t)
	const workers = 12
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- a.raw("user-manager", "POST", base+"products", fmt.Sprintf(`{"name":"Concurrent %d"}`, i))
		}(i)
	}
	wg.Wait()
	close(results)
	ids := make(map[string]bool)
	for result := range results {
		expect(t, result, 201)
		id := object(t, result)["id"].(string)
		if ids[id] {
			t.Fatal("concurrent create reused an ID")
		}
		ids[id] = true
	}
	var allIDs []string
	for id := range ids {
		allIDs = append(allIDs, id)
	}
	sort.Strings(allIDs)
	failures := make(chan string, workers)
	for _, id := range allIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			path := base + "products/" + id
			for i := 0; i < 10; i++ {
				result := a.raw("user-manager", "PATCH", path, `{"description":"updated"}`)
				if result.Code != 200 {
					failures <- fmt.Sprintf("update %s: %d", id, result.Code)
					return
				}
				result = a.raw("user-viewer", "GET", base+"products?sort=updated_at", "")
				if result.Code != 200 || !json.Valid(result.Body.Bytes()) {
					failures <- fmt.Sprintf("list during update: %d", result.Code)
					return
				}
			}
			if result := a.raw("user-admin", "DELETE", path, ""); result.Code != 204 {
				failures <- fmt.Sprintf("delete %s: %d", id, result.Code)
			}
		}(id)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	remaining := a.call(t, "user-admin", "GET", base+"products", nil)
	expect(t, remaining, 200)
	if object(t, remaining)["total"] != float64(2) {
		t.Fatal("concurrent create/update/delete left an unexpected record")
	}
}

func TestPatchAndPutSemantics(t *testing.T) {
	a := newAPI(t)
	created := a.call(t, "user-manager", "POST", base+"products", map[string]any{"name": "Original", "description": "Keep on PATCH", "active": false})
	expect(t, created, 201)
	before := object(t, created)
	path := base + "products/" + before["id"].(string)
	patched := a.call(t, "user-manager", "PATCH", path, map[string]any{"name": "Patched"})
	expect(t, patched, 200)
	if object(t, patched)["description"] != "Keep on PATCH" || object(t, patched)["active"] != false {
		t.Fatal("PATCH removed omitted attributes")
	}
	replaced := a.call(t, "user-manager", "PUT", path, map[string]any{"name": "Replaced"})
	expect(t, replaced, 200)
	after := object(t, replaced)
	if _, exists := after["description"]; exists || after["active"] != true {
		t.Fatal("PUT did not replace attributes and restore defaults")
	}
	for _, key := range []string{"id", "tenant_id", "created_at"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Errorf("PUT changed immutable field %s", key)
		}
	}
}
