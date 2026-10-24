package rbac

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// jsonNumber aliases json.Number so toFloat can accept decoded JSON numbers.
type jsonNumber = json.Number

// defaultPage and maxPage bound pagination.
const (
	defaultPage = 20
	maxPage     = 100
)

// requiredCreateFields lists the fields a create request must supply.
var requiredCreateFields = map[string][]string{
	"products":   {"sku", "name"},
	"prices":     {"product", "amount"},
	"orders":     {"customer", "status"},
	"customers":  {"name", "email"},
	"invoices":   {"order", "amount"},
	"payments":   {"order", "amount"},
	"refunds":    {"order", "amount"},
	"inventory":  {"product", "quantity"},
	"api-keys":   {"name"},
	"audit-logs": {}, // audit logs are append-only and not created via API
}

// stringFields must be strings when present.
var stringFields = map[string]bool{
	"sku": true, "name": true, "email": true, "status": true,
	"product": true, "order": true, "customer": true, "reason": true,
	"currency": true, "warehouse": true, "expiresAt": true, "key": true,
}

// validateResource enforces per-resource field presence (on create) and basic
// types. It returns a *apiError on the first violation.
func validateResource(resource string, in map[string]any, create bool) *apiError {
	if resource == "audit-logs" {
		// Audit logs are immutable and created only by the system.
		if create {
			return newErr(statusBadRequest, errCodeBadRequest, "audit-logs are append-only")
		}
		return nil
	}

	if create {
		for _, f := range requiredCreateFields[resource] {
			if in == nil {
				return newErr(statusBadRequest, errCodeBadRequest, "missing required field: "+f)
			}
			if v, ok := in[f]; !ok || isBlank(v) {
				return newErr(statusBadRequest, errCodeBadRequest, "missing required field: "+f)
			}
		}
	}

	// Type checks for whatever fields are supplied.
	for _, f := range []string{"amount", "quantity", "unitPrice"} {
		if v, ok := in[f]; ok {
			if !isNumber(v) {
				return newErr(statusBadRequest, errCodeBadRequest, "field must be numeric: "+f)
			}
			if f == "quantity" {
				// quantity must be a non-negative integer
				if num, ok := toFloat(v); !ok || num < 0 || num != trunc(num) {
					return newErr(statusBadRequest, errCodeBadRequest, "field must be a non-negative integer: quantity")
				}
			}
		}
	}
	for f := range stringFields {
		if v, ok := in[f]; ok {
			if _, ok := v.(string); !ok {
				return newErr(statusBadRequest, errCodeBadRequest, "field must be a string: "+f)
			}
		}
	}
	if email, ok := in["email"].(string); ok {
		if !strings.Contains(email, "@") {
			return newErr(statusBadRequest, errCodeBadRequest, "field must be a valid email: email")
		}
	}
	return nil
}

func isBlank(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) == ""
	case nil:
		return true
	default:
		return false
	}
}

func isNumber(v any) bool {
	_, ok := toFloat(v)
	return ok
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case jsonNumber:
		f, err := t.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func trunc(f float64) float64 {
	i := int64(f)
	return float64(i)
}

// parsePageFilter reads standard pagination and filter query parameters.
func parsePageFilter(q url.Values) pageConfig {
	cfg := pageConfig{}
	// limit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Page.Limit = n
		} else {
			// caller will treat negative/0 as default; non-numeric -> bad
			cfg.Page.Limit = -1
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Page.Offset = n
		} else {
			cfg.Page.Offset = -1
		}
	}
	cfg.Filter.Owner = q.Get("owner")
	cfg.Filter.Status = q.Get("status")
	cfg.Filter.Parent = q.Get("parent")
	return cfg
}
