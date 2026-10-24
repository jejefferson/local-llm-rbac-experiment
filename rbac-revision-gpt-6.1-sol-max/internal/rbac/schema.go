package rbac

import (
	"encoding/json"
	"net/mail"
	"sort"
	"strconv"
	"strings"
)

type field struct {
	required bool
	fallback any
	check    func(any) bool
}

type resourceSpec struct {
	fields map[string]field
	// References are immutable and always resolved inside the selected tenant.
	refs map[string]string
}

func textField(required bool, max int) field {
	return field{required: required, check: func(value any) bool {
		v, ok := value.(string)
		return ok && len(v) <= max && (!required || strings.TrimSpace(v) != "")
	}}
}

func idField(required bool) field {
	return field{required: required, check: func(value any) bool {
		v, ok := value.(string)
		return ok && validID(v)
	}}
}

func intField(required bool, minimum int64) field {
	return field{required: required, check: func(value any) bool {
		v, ok := value.(json.Number)
		if !ok {
			return false
		}
		n, err := strconv.ParseInt(v.String(), 10, 64)
		return err == nil && n >= minimum
	}}
}

func boolField(fallback bool) field {
	return field{fallback: fallback, check: func(value any) bool {
		_, ok := value.(bool)
		return ok
	}}
}

func enumField(fallback string, choices ...string) field {
	return field{fallback: fallback, check: func(value any) bool {
		v, ok := value.(string)
		if ok {
			for _, choice := range choices {
				if v == choice {
					return true
				}
			}
		}
		return false
	}}
}

var currencyField = field{required: true, check: func(value any) bool {
	v, ok := value.(string)
	if !ok || len(v) != 3 {
		return false
	}
	for _, c := range v {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}}

var specs = map[string]resourceSpec{
	"products": {fields: map[string]field{
		"name": textField(true, 200), "description": textField(false, 4000),
		"sku": textField(false, 100), "active": boolField(true),
	}},
	"prices": {fields: map[string]field{
		"product_id": idField(true), "amount": intField(true, 0),
		"currency": currencyField, "active": boolField(true),
	}, refs: map[string]string{"product_id": "products"}},
	"orders": {fields: map[string]field{
		"customer_id": idField(true), "total": intField(true, 0), "currency": currencyField,
		"status": enumField("pending", "pending", "confirmed", "processing", "paid", "shipped", "completed", "cancelled"),
		"notes":  textField(false, 4000),
	}, refs: map[string]string{"customer_id": "customers"}},
	"customers": {fields: map[string]field{
		"name": textField(true, 200), "phone": textField(false, 100),
		"email": {required: true, check: func(value any) bool {
			v, ok := value.(string)
			if !ok || len(v) > 254 {
				return false
			}
			address, err := mail.ParseAddress(v)
			return err == nil && address.Address == v
		}},
	}},
	"invoices": {fields: map[string]field{
		"order_id": idField(true), "amount": intField(true, 0), "currency": currencyField,
		"number": textField(false, 100),
		"status": enumField("draft", "draft", "open", "paid", "void", "uncollectible"),
	}, refs: map[string]string{"order_id": "orders"}},
	"payments": {fields: map[string]field{
		"order_id": idField(true), "invoice_id": idField(false),
		"amount": intField(true, 0), "currency": currencyField, "method": textField(false, 100),
		"status": enumField("pending", "pending", "succeeded", "failed", "refunded"),
	}, refs: map[string]string{"order_id": "orders", "invoice_id": "invoices"}},
	"refunds": {fields: map[string]field{
		"payment_id": idField(true), "amount": intField(true, 1),
		"reason": textField(false, 1000), "status": enumField("pending", "pending", "succeeded", "failed"),
	}, refs: map[string]string{"payment_id": "payments"}},
	"inventory": {fields: map[string]field{
		"product_id": idField(true), "quantity": intField(true, 0), "location": textField(false, 200),
	}, refs: map[string]string{"product_id": "products"}},
	"api-keys": {fields: map[string]field{
		"name": textField(true, 200), "enabled": boolField(true),
		"scopes": {fallback: []any{}, check: func(value any) bool {
			values, ok := value.([]any)
			if !ok || len(values) > 100 {
				return false
			}
			for _, item := range values {
				v, ok := item.(string)
				if !ok || strings.TrimSpace(v) == "" || len(v) > 100 {
					return false
				}
			}
			return true
		}},
	}},
	"audit-logs": {fields: map[string]field{
		"actor_id": idField(true), "action": textField(true, 30),
		"resource": textField(true, 30), "resource_id": idField(true),
	}},
}

func resourceNames() []string {
	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func relation(parent, child string) string {
	for key, resource := range specs[child].refs {
		if resource == parent {
			return key
		}
	}
	return ""
}

func validateData(t *tenant, resource string, input map[string]any, current *record, replace bool) (map[string]any, *apiError) {
	spec := specs[resource]
	data := make(map[string]any)
	if current != nil && !replace {
		data = clone(current.Data).(map[string]any)
	} else {
		for key, rule := range spec.fields {
			if rule.fallback != nil {
				data[key] = clone(rule.fallback)
			}
		}
	}
	for key, value := range input {
		rule, ok := spec.fields[key]
		if !ok {
			return nil, badInput("unknown or read-only field: " + key)
		}
		if !rule.check(value) {
			return nil, badInput("invalid field: " + key)
		}
		data[key] = clone(value)
	}
	// A payment attached to an invoice belongs to that invoice's order. Nested
	// invoice creation need not repeat the derived order_id.
	if resource == "payments" && data["order_id"] == nil && data["invoice_id"] != nil {
		invoice := t.Records["invoices"][data["invoice_id"].(string)]
		if invoice == nil {
			return nil, notFound("referenced invoice not found")
		}
		data["order_id"] = invoice.Data["order_id"]
	}
	for key, rule := range spec.fields {
		if rule.required && data[key] == nil {
			return nil, badInput("missing field: " + key)
		}
	}
	for key, parentResource := range spec.refs {
		if current != nil && data[key] != current.Data[key] {
			return nil, conflict("immutable_relation", key+" cannot be changed")
		}
		if value, ok := data[key]; ok && t.Records[parentResource][value.(string)] == nil {
			return nil, notFound("referenced " + parentResource + " record not found")
		}
	}
	if resource == "payments" && data["invoice_id"] != nil {
		invoice := t.Records["invoices"][data["invoice_id"].(string)]
		if invoice.Data["order_id"] != data["order_id"] {
			return nil, badInput("invoice_id and order_id must refer to the same order")
		}
	}
	if resource == "api-keys" && current != nil {
		data["key"] = current.Data["key"]
	}
	return data, nil
}

func hasChildren(t *tenant, item *record) bool {
	for childResource, spec := range specs {
		for key, parentResource := range spec.refs {
			if parentResource != item.Resource {
				continue
			}
			for _, child := range t.Records[childResource] {
				if child.Data[key] == item.ID {
					return true
				}
			}
		}
	}
	return false
}
