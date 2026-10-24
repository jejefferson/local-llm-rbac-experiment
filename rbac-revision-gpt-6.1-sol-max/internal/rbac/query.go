package rbac

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"time"
)

type listQuery struct {
	limit   int
	offset  int
	sort    string
	desc    bool
	filters map[string]string
}

func parseQuery(raw, resource string) (listQuery, *apiError) {
	q := listQuery{limit: 20, sort: "id", filters: make(map[string]string)}
	if resource == "members" {
		q.sort = "user_id"
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return q, badInput("invalid query string")
	}
	for key, items := range values {
		if len(items) != 1 {
			return q, badInput("query parameters must not be repeated")
		}
		value := items[0]
		switch key {
		case "limit":
			q.limit, err = strconv.Atoi(value)
			if err != nil || q.limit < 1 || q.limit > 100 {
				return q, badInput("limit must be an integer from 1 to 100")
			}
		case "offset":
			q.offset, err = strconv.Atoi(value)
			if err != nil || q.offset < 0 {
				return q, badInput("offset must be a nonnegative integer")
			}
		case "sort":
			if resource == "members" {
				if value != "user_id" && value != "role" {
					return q, badInput("sort must be user_id or role")
				}
			} else if value != "id" && value != "created_at" && value != "updated_at" {
				return q, badInput("sort must be id, created_at, or updated_at")
			}
			q.sort = value
		case "order":
			if value != "asc" && value != "desc" {
				return q, badInput("order must be asc or desc")
			}
			q.desc = value == "desc"
		default:
			if !filterable(resource, key) {
				return q, badInput("unsupported filter: " + key)
			}
			q.filters[key] = value
		}
	}
	return q, nil
}

func filterable(resource, key string) bool {
	if resource == "members" {
		return key == "user_id" || key == "role"
	}
	if key == "id" || (key == "owner_id" && (resource == "orders" || resource == "invoices")) {
		return true
	}
	_, ok := specs[resource].fields[key]
	return ok && key != "scopes"
}

func scalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case role:
		return string(v)
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

func (q listQuery) matches(item map[string]any) bool {
	for key, expected := range q.filters {
		value, exists := item[key]
		if !exists || scalar(value) != expected {
			return false
		}
	}
	return true
}

func (q listQuery) page(items []map[string]any) response {
	identity := "id"
	if q.sort == "user_id" || q.sort == "role" {
		identity = "user_id"
	}
	sort.Slice(items, func(i, j int) bool {
		left, right := scalar(items[i][q.sort]), scalar(items[j][q.sort])
		cmp := 0
		if q.sort == "created_at" || q.sort == "updated_at" {
			a, _ := time.Parse(time.RFC3339Nano, left)
			b, _ := time.Parse(time.RFC3339Nano, right)
			if a.Before(b) {
				cmp = -1
			} else if a.After(b) {
				cmp = 1
			}
		} else if left < right {
			cmp = -1
		} else if left > right {
			cmp = 1
		}
		if cmp == 0 {
			left, right = scalar(items[i][identity]), scalar(items[j][identity])
			if left < right {
				cmp = -1
			} else if left > right {
				cmp = 1
			}
		}
		if q.desc {
			return cmp > 0
		}
		return cmp < 0
	})
	start := q.offset
	if start > len(items) {
		start = len(items)
	}
	end := start + q.limit
	if end > len(items) {
		end = len(items)
	}
	return response{status: 200, body: map[string]any{
		"data": items[start:end], "total": len(items), "limit": q.limit, "offset": q.offset,
	}}
}
