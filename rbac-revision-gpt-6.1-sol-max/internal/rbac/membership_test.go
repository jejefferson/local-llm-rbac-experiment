package rbac_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMemberPermissionMatrix(t *testing.T) {
	for _, role := range []string{"admin", "manager", "viewer"} {
		for _, operation := range []string{"list", "read", "create", "patch", "put", "delete"} {
			t.Run(role+"/"+operation, func(t *testing.T) {
				a := newAPI(t)
				path, method, status := base+"members", "GET", 200
				var body any
				switch operation {
				case "read":
					path += "/user-viewer"
				case "create":
					method, status = "POST", 201
					body = map[string]any{"user_id": "user-outsider", "role": "manager"}
				case "patch", "put":
					path += "/user-viewer"
					method = strings.ToUpper(operation)
					body = map[string]any{"role": "manager"}
				case "delete":
					path += "/user-viewer"
					method, status = "DELETE", 204
				}
				if role != "admin" {
					status = 403
				}
				expect(t, a.call(t, "user-"+role, method, path, body), status)
			})
		}
	}
}

func TestMembershipChangesAreImmediateAndTenantSpecific(t *testing.T) {
	a := newAPI(t)
	product := map[string]any{"name": "Membership change test"}
	expect(t, a.call(t, "user-viewer", "POST", base+"products", product), 403)
	expect(t, a.call(t, "user-admin", "PATCH", base+"members/user-viewer", map[string]any{"role": "manager"}), 200)
	expect(t, a.call(t, "user-viewer", "POST", base+"products", product), 201)
	// A manager still cannot promote itself, including with forged headers.
	expect(t, a.raw("user-viewer", "PATCH", base+"members/user-viewer", `{"role":"admin"}`, map[string]string{"X-Role": "admin", "X-User-ID": "user-admin"}), 403)
	expect(t, a.call(t, "user-admin", "PUT", base+"members/user-viewer", map[string]any{"role": "viewer"}), 200)
	expect(t, a.call(t, "user-viewer", "POST", base+"products", product), 403)
	expect(t, a.call(t, "user-admin", "DELETE", base+"members/user-viewer", nil), 204)
	expect(t, a.call(t, "user-viewer", "GET", base+"products", nil), 403)
	expect(t, a.call(t, "user-viewer", "GET", base+"orders/order-a-viewer", nil), 403)
	expect(t, a.call(t, "user-viewer", "POST", "/tenants/tenant-b/products", product), 201)
	expect(t, a.call(t, "user-admin", "PATCH", "/tenants/tenant-b/members/user-viewer", map[string]any{"role": "admin"}), 403)
	// Rejoining restores the original server-side identity and its owned records.
	expect(t, a.call(t, "user-admin", "POST", base+"members", map[string]any{"user_id": "user-viewer", "role": "viewer"}), 201)
	expect(t, a.call(t, "user-viewer", "GET", base+"orders/order-a-viewer", nil), 200)
	expect(t, a.call(t, "user-viewer", "GET", base+"invoices/invoice-a-viewer", nil), 200)
}

func TestInvalidMembershipChangesDoNotMutateState(t *testing.T) {
	a := newAPI(t)
	before := snapshot(t, a)
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "members", `{"user_id":"user-outsider","role":"owner"}`, 400},
		{"POST", "members", `{"user_id":"user-outsider","role":"Admin"}`, 400},
		{"POST", "members", `{"user_id":"user-outsider","role":null}`, 400},
		{"POST", "members", `{"role":"viewer"}`, 400},
		{"POST", "members", `{"user_id":"missing","role":"viewer"}`, 404},
		{"POST", "members", `{"user_id":"user-viewer","role":"admin"}`, 409},
		{"POST", "members", `{"user_id":"user-outsider","role":"viewer","tenant_id":"tenant-b"}`, 400},
		{"PATCH", "members/user-viewer", `{"user_id":"user-admin","role":"admin"}`, 400},
		{"PATCH", "members/user-viewer", `{"role":"invalid"}`, 400},
		{"PATCH", "members/missing", `{"role":"viewer"}`, 404},
		{"DELETE", "members/missing", "", 404},
		{"PATCH", "members/user-admin-2", `{"role":"viewer"}`, 404},
		{"DELETE", "members/user-admin-2", "", 404},
		{"PATCH", "members/user-admin", `{"role":"viewer"}`, 409},
		{"PUT", "members/user-admin", `{"role":"manager"}`, 409},
		{"DELETE", "members/user-admin", "", 409},
	} {
		t.Run(test.method+"/"+test.path+"/"+test.body, func(t *testing.T) {
			expect(t, a.raw("user-admin", test.method, base+test.path, test.body), test.status)
		})
	}
	for _, user := range []string{"user-manager", "user-viewer"} {
		expect(t, a.raw(user, "PATCH", base+"members/"+user, `{"role":"admin"}`, map[string]string{"X-Role": "admin"}), 403)
	}
	if before != snapshot(t, a) {
		t.Fatal("a rejected membership change modified state")
	}
}

func TestAdminCanTransferAdministration(t *testing.T) {
	a := newAPI(t)
	expect(t, a.call(t, "user-admin", "POST", base+"members", map[string]any{"user_id": "user-outsider", "role": "admin"}), 201)
	expect(t, a.call(t, "user-admin", "PATCH", base+"members/user-admin", map[string]any{"role": "viewer"}), 200)
	expect(t, a.call(t, "user-admin", "GET", base+"members", nil), 403)
	expect(t, a.call(t, "user-outsider", "GET", base+"members", nil), 200)
	expect(t, a.call(t, "user-outsider", "DELETE", base+"members/user-outsider", nil), 409)
	expect(t, a.call(t, "user-outsider", "PATCH", base+"members/user-outsider", map[string]any{"role": "admin"}), 200)
	expect(t, a.call(t, "user-outsider", "DELETE", base+"members/user-admin", nil), 204)
	expect(t, a.call(t, "user-admin", "GET", base+"products", nil), 403)
}

func TestConcurrentLastAdminProtection(t *testing.T) {
	for _, method := range []string{"PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			a := newAPI(t)
			expect(t, a.call(t, "user-admin", "POST", base+"members", map[string]any{"user_id": "user-outsider", "role": "admin"}), 201)
			start := make(chan struct{})
			type result struct {
				user string
				res  *httptest.ResponseRecorder
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			for _, user := range []string{"user-admin", "user-outsider"} {
				wg.Add(1)
				go func(user string) {
					defer wg.Done()
					<-start
					results <- result{user, a.raw(user, method, base+"members/"+user, `{"role":"viewer"}`)}
				}(user)
			}
			close(start)
			wg.Wait()
			close(results)
			successes, conflicts, remainingAdmin := 0, 0, ""
			for result := range results {
				switch result.res.Code {
				case 200, 204:
					successes++
				case 409:
					conflicts++
					remainingAdmin = result.user
				default:
					t.Fatalf("unexpected response: %d %s", result.res.Code, result.res.Body.String())
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("concurrent removal/demotion: successes=%d conflicts=%d", successes, conflicts)
			}
			members := a.call(t, remainingAdmin, "GET", base+"members?role=admin", nil)
			expect(t, members, 200)
			if object(t, members)["total"] != float64(1) {
				t.Fatal("tenant did not retain exactly one administrator")
			}
		})
	}
}

func TestConcurrentRevocationAndWritesAreLinearizable(t *testing.T) {
	a := newAPI(t)
	expect(t, a.call(t, "user-admin", "POST", base+"members", map[string]any{"user_id": "user-outsider", "role": "manager"}), 201)
	expect(t, a.raw("user-outsider", "POST", base+"products", `{"name":"Race baseline"}`), 201)
	expect(t, a.raw("user-admin", "PATCH", base+"members/user-outsider", `{"role":"viewer"}`), 200)
	expect(t, a.raw("user-outsider", "POST", base+"products", `{"name":"Denied baseline"}`), 403)
	const workers = 6
	start := make(chan struct{})
	type workerResult struct {
		created int
		err     string
	}
	results := make(chan workerResult, workers+1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 30; i++ {
			for _, role := range []string{"manager", "viewer"} {
				result := a.raw("user-admin", "PATCH", base+"members/user-outsider", `{"role":"`+role+`"}`)
				if result.Code != 200 {
					results <- workerResult{err: fmt.Sprintf("membership update: %d %s", result.Code, result.Body.String())}
					return
				}
			}
		}
		results <- workerResult{}
	}()
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			created := 0
			for i := 0; i < 40; i++ {
				body := fmt.Sprintf(`{"name":"Race %d %d"}`, worker, i)
				result := a.raw("user-outsider", "POST", base+"products", body)
				if result.Code == 201 {
					created++
				} else if result.Code != 403 {
					results <- workerResult{err: fmt.Sprintf("write during role change: %d %s", result.Code, result.Body.String())}
					return
				}
			}
			results <- workerResult{created: created}
		}(worker)
	}
	close(start)
	wg.Wait()
	close(results)
	successfulWrites := 1
	for result := range results {
		if result.err != "" {
			t.Fatal(result.err)
		}
		successfulWrites += result.created
	}
	expect(t, a.raw("user-admin", "DELETE", base+"members/user-outsider", ""), 204)
	for i := 0; i < 10; i++ {
		expect(t, a.raw("user-outsider", "POST", base+"products", `{"name":"After revocation"}`), 403)
	}
	// Audit IDs are assigned inside the transaction, giving a serialized history
	// independent of when concurrent HTTP responses happened to be delivered.
	currentRole, auditedWrites := "", 0
	for offset := 0; ; offset += 100 {
		result := a.call(t, "user-admin", "GET", base+fmt.Sprintf("audit-logs?limit=100&offset=%d&sort=id", offset), nil)
		expect(t, result, 200)
		entries := rows(t, result)
		for _, entry := range entries {
			if entry["resource"] == "members" && entry["resource_id"] == "user-outsider" {
				details := entry["details"].(map[string]any)
				if previous, ok := details["previous_role"]; ok && previous != currentRole {
					t.Fatalf("membership audit history is inconsistent: %v, role %q", entry, currentRole)
				}
				if entry["action"] == "delete" {
					currentRole = ""
				} else {
					currentRole = details["role"].(string)
				}
			}
			if entry["actor_id"] == "user-outsider" && entry["resource"] == "products" {
				if currentRole != "manager" && currentRole != "admin" {
					t.Fatalf("write committed while role was %q: %v", currentRole, entry)
				}
				auditedWrites++
			}
		}
		if len(entries) < 100 {
			break
		}
	}
	if currentRole != "" || auditedWrites != successfulWrites {
		t.Fatalf("revocation/write history: final role=%q audited=%d HTTP successes=%d", currentRole, auditedWrites, successfulWrites)
	}
	products := a.call(t, "user-admin", "GET", base+"products", nil)
	expect(t, products, 200)
	if object(t, products)["total"] != float64(2+successfulWrites) {
		t.Fatal("successful HTTP writes and stored records differ")
	}
}
