package rbac_test

import (
	"strings"
	"testing"
)

func TestMalformedInputDoesNotMutateState(t *testing.T) {
	a := newAPI(t)
	before := snapshot(t, a)
	tests := []struct {
		name, method, path, body string
		status                   int
		headers                  map[string]string
	}{
		{name: "empty", method: "POST", path: "products", body: "", status: 400},
		{name: "null", method: "POST", path: "products", body: "null", status: 400},
		{name: "array", method: "POST", path: "products", body: "[]", status: 400},
		{name: "primitive", method: "POST", path: "products", body: "true", status: 400},
		{name: "empty-object", method: "POST", path: "products", body: "{}", status: 400},
		{name: "broken-json", method: "POST", path: "products", body: `{"name":`, status: 400},
		{name: "duplicate-name", method: "POST", path: "products", body: `{"name":"First","name":"Second"}`, status: 400},
		{name: "duplicate-role", method: "POST", path: "members", body: `{"user_id":"user-outsider","role":"viewer","role":"admin"}`, status: 400},
		{name: "trailing-object", method: "POST", path: "products", body: `{"name":"First"} {"name":"Second"}`, status: 400},
		{name: "trailing-garbage", method: "POST", path: "products", body: `{"name":"First"} rubbish`, status: 400},
		{name: "missing-name", method: "POST", path: "products", body: `{"active":true}`, status: 400},
		{name: "blank-name", method: "POST", path: "products", body: `{"name":"  "}`, status: 400},
		{name: "long-name", method: "POST", path: "products", body: `{"name":"` + strings.Repeat("x", 201) + `"}`, status: 400},
		{name: "wrong-type", method: "POST", path: "products", body: `{"name":7}`, status: 400},
		{name: "unknown-field", method: "POST", path: "products", body: `{"name":"Test","admin":true}`, status: 400},
		{name: "forged-tenant", method: "PATCH", path: "products/product-a-1", body: `{"tenant_id":"tenant-b"}`, status: 400},
		{name: "forged-id", method: "PATCH", path: "products/product-a-1", body: `{"id":"product-b-1"}`, status: 400},
		{name: "forged-time", method: "PATCH", path: "products/product-a-1", body: `{"created_at":"2020-01-01T00:00:00Z"}`, status: 400},
		{name: "bad-enum", method: "PATCH", path: "orders/order-a-viewer", body: `{"status":"root"}`, status: 400},
		{name: "negative-inventory", method: "PATCH", path: "inventory/inventory-a-1", body: `{"quantity":-1}`, status: 400},
		{name: "fraction", method: "PATCH", path: "prices/price-a-1", body: `{"amount":1.5}`, status: 400},
		{name: "overflow", method: "PATCH", path: "prices/price-a-1", body: `{"amount":9223372036854775808}`, status: 400},
		{name: "number-string", method: "PATCH", path: "prices/price-a-1", body: `{"amount":"100"}`, status: 400},
		{name: "bad-currency", method: "PATCH", path: "prices/price-a-1", body: `{"currency":"usd"}`, status: 400},
		{name: "bad-email", method: "PATCH", path: "customers/customer-a-1", body: `{"email":"not-an-address"}`, status: 400},
		{name: "invalid-scopes", method: "POST", path: "api-keys", body: `{"name":"Test","scopes":[3]}`, status: 400},
		{name: "forged-api-key", method: "POST", path: "api-keys", body: `{"name":"Test","key":"forged"}`, status: 400},
		{name: "partial-put", method: "PUT", path: "prices/price-a-1", body: `{"amount":100}`, status: 400},
		{name: "empty-patch", method: "PATCH", path: "products/product-a-1", body: `{}`, status: 400},
		{name: "null-patch", method: "PATCH", path: "products/product-a-1", body: `{"name":null}`, status: 400},
		{name: "body-too-large", method: "POST", path: "products", body: `{"name":"` + strings.Repeat("x", 1<<20) + `"}`, status: 413},
		{name: "oversized-trailing-whitespace", method: "POST", path: "products", body: `{"name":"Test"}` + strings.Repeat(" ", 1<<20), status: 413},
		{name: "too-deep", method: "POST", path: "products", body: `{"name":` + strings.Repeat("[", 65) + `"a"` + strings.Repeat("]", 65) + `}`, status: 400},
		{name: "wrong-content-type", method: "POST", path: "products", body: `{"name":"Test"}`, status: 415, headers: map[string]string{"Content-Type": "text/plain"}},
		{name: "missing-content-type", method: "POST", path: "products", body: `{"name":"Test"}`, status: 415, headers: map[string]string{"Content-Type": ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expect(t, a.raw("user-admin", test.method, base+test.path, test.body, test.headers), test.status)
		})
	}
	if before != snapshot(t, a) {
		t.Fatal("invalid input changed data or audit state")
	}
	// Authorization takes precedence over body and media-type errors.
	expect(t, a.raw("user-viewer", "POST", base+"products", "{", map[string]string{"Content-Type": "text/plain"}), 403)
}

func TestIntegerAmountsRetainPrecision(t *testing.T) {
	a := newAPI(t)
	const amount = "9007199254740993"
	created := a.raw("user-admin", "POST", base+"prices", `{"product_id":"product-a-1","amount":`+amount+`,"currency":"USD"}`)
	expect(t, created, 201)
	if !strings.Contains(created.Body.String(), `"amount":`+amount) {
		t.Fatal("integer amount lost precision in create response")
	}
	listed := a.call(t, "user-viewer", "GET", base+"prices?amount="+amount, nil)
	expect(t, listed, 200)
	if len(rows(t, listed)) != 1 || !strings.Contains(listed.Body.String(), `"amount":`+amount) {
		t.Fatal("integer amount lost precision in storage or filtering")
	}
}

func TestForeignReferencesAndImmutableParents(t *testing.T) {
	a := newAPI(t)
	before := snapshot(t, a)
	for _, test := range []struct{ resource, body string }{
		{"prices", `{"product_id":"product-b-1","amount":1,"currency":"USD"}`},
		{"orders", `{"customer_id":"customer-b-1","total":1,"currency":"USD"}`},
		{"invoices", `{"order_id":"order-b-admin","amount":1,"currency":"USD"}`},
		{"payments", `{"order_id":"order-b-admin","amount":1,"currency":"USD"}`},
		{"payments", `{"order_id":"order-a-viewer","invoice_id":"invoice-b-admin","amount":1,"currency":"USD"}`},
		{"refunds", `{"payment_id":"payment-b-1","amount":1}`},
		{"inventory", `{"product_id":"product-b-1","quantity":1}`},
	} {
		t.Run(test.resource+"/"+test.body, func(t *testing.T) {
			expect(t, a.raw("user-admin", "POST", base+test.resource, test.body), 404)
		})
	}
	for _, test := range []struct{ path, body string }{
		{"prices/price-a-1", `{"product_id":"product-a-2"}`},
		{"orders/order-a-viewer", `{"customer_id":"customer-a-2"}`},
		{"invoices/invoice-a-viewer", `{"order_id":"order-a-other"}`},
		{"payments/payment-a-1", `{"order_id":"order-a-other"}`},
		{"payments/payment-a-1", `{"invoice_id":"invoice-a-other"}`},
		{"refunds/refund-a-1", `{"payment_id":"payment-b-1"}`},
		{"inventory/inventory-a-1", `{"product_id":"product-a-2"}`},
	} {
		expect(t, a.raw("user-admin", "PATCH", base+test.path, test.body), 409)
	}
	expect(t, a.raw("user-admin", "POST", base+"payments", `{"order_id":"order-a-other","invoice_id":"invoice-a-viewer","amount":1,"currency":"USD"}`), 400)
	if before != snapshot(t, a) {
		t.Fatal("invalid references modified state")
	}
}

func TestNestedResourceCRUD(t *testing.T) {
	tests := []struct {
		path, child, foreignKey, parentID, create, patch string
	}{
		{"products/product-a-1/prices", "prices", "product_id", "product-a-1", `{"amount":10,"currency":"USD"}`, `{"amount":20}`},
		{"products/product-a-1/inventory", "inventory", "product_id", "product-a-1", `{"quantity":10}`, `{"quantity":20}`},
		{"customers/customer-a-1/orders", "orders", "customer_id", "customer-a-1", `{"total":10,"currency":"USD"}`, `{"status":"confirmed"}`},
		{"orders/order-a-viewer/invoices", "invoices", "order_id", "order-a-viewer", `{"amount":10,"currency":"USD"}`, `{"status":"open"}`},
		{"orders/order-a-viewer/payments", "payments", "order_id", "order-a-viewer", `{"amount":10,"currency":"USD"}`, `{"status":"succeeded"}`},
		{"invoices/invoice-a-viewer/payments", "payments", "invoice_id", "invoice-a-viewer", `{"amount":10,"currency":"USD"}`, `{"status":"succeeded"}`},
		{"payments/payment-a-1/refunds", "refunds", "payment_id", "payment-a-1", `{"amount":10}`, `{"reason":"Updated"}`},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			a := newAPI(t)
			created := a.raw("user-admin", "POST", base+test.path, test.create)
			expect(t, created, 201)
			item := object(t, created)
			if item[test.foreignKey] != test.parentID {
				t.Fatal("nested create did not use the parent from the URL")
			}
			id := item["id"].(string)
			path := base + test.path + "/" + id
			expect(t, a.raw("user-admin", "GET", path, ""), 200)
			expect(t, a.raw("user-admin", "GET", base+test.child+"/"+id, ""), 200)
			expect(t, a.raw("user-admin", "PATCH", path, test.patch), 200)
			expect(t, a.raw("user-admin", "PUT", path, test.create), 200)
			listed := a.raw("user-admin", "GET", base+test.path, "")
			expect(t, listed, 200)
			for _, listed := range rows(t, listed) {
				if listed[test.foreignKey] != test.parentID {
					t.Fatalf("nested list returned an unrelated record: %v", listed)
				}
			}
			expect(t, a.raw("user-admin", "DELETE", path, ""), 204)
			expect(t, a.raw("user-admin", "GET", path, ""), 404)
		})
	}
}

func TestNestedParentChecksAndDeletionRestrictions(t *testing.T) {
	a := newAPI(t)
	deep := "customers/customer-a-1/orders/order-a-viewer/invoices/invoice-a-viewer/payments/payment-a-1/refunds/refund-a-1"
	expect(t, a.raw("user-admin", "GET", base+deep, ""), 200)
	expect(t, a.raw("user-admin", "GET", base+strings.Replace(deep, "customer-a-1", "customer-a-2", 1), ""), 404)
	expect(t, a.raw("user-admin", "GET", base+"products/product-a-2/prices/price-a-1", ""), 404)
	before := snapshot(t, a)
	expect(t, a.raw("user-admin", "POST", base+"products/product-a-1/prices", `{"product_id":"product-a-2","amount":1,"currency":"USD"}`), 400)
	expect(t, a.raw("user-manager", "POST", base+"products/product-a-1/prices", `{"amount":1,"currency":"USD"}`), 403)
	expect(t, a.raw("user-admin", "DELETE", base+"products/product-a-1", ""), 409)
	expect(t, a.raw("user-admin", "DELETE", base+"customers/customer-a-1", ""), 409)
	expect(t, a.raw("user-admin", "DELETE", base+"orders/order-a-viewer", ""), 409)
	expect(t, a.raw("user-admin", "DELETE", base+"invoices/invoice-a-viewer", ""), 409)
	expect(t, a.raw("user-admin", "DELETE", base+"payments/payment-a-1", ""), 409)
	if before != snapshot(t, a) {
		t.Fatal("a rejected nested operation or restricted delete changed state")
	}
	created := a.raw("user-admin", "POST", base+"products", `{"name":"Parent to delete"}`)
	expect(t, created, 201)
	productID := object(t, created)["id"].(string)
	price := a.raw("user-admin", "POST", base+"products/"+productID+"/prices", `{"amount":1,"currency":"USD"}`)
	expect(t, price, 201)
	priceID := object(t, price)["id"].(string)
	expect(t, a.raw("user-admin", "DELETE", base+"products/"+productID, ""), 409)
	expect(t, a.raw("user-admin", "DELETE", base+"prices/"+priceID, ""), 204)
	expect(t, a.raw("user-admin", "DELETE", base+"products/"+productID, ""), 204)
}
