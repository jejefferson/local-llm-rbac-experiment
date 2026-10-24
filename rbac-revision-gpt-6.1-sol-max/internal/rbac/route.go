package rbac

import (
	"net/url"
	"strings"
)

type pathParent struct {
	resource string
	id       string
	field    string // Foreign key in the next path resource.
}

type route struct {
	tenantID string
	resource string
	id       string
	parents  []pathParent
}

func parseRoute(path string) (route, bool) {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) < 4 || parts[0] != "" {
		return route{}, false
	}
	for i := 1; i < len(parts); i++ {
		decoded, err := url.PathUnescape(parts[i])
		if err != nil || !validID(decoded) {
			return route{}, false
		}
		parts[i] = decoded
	}
	if parts[1] != "tenants" {
		return route{}, false
	}
	result := route{tenantID: parts[2]}
	for i := 3; i < len(parts); i += 2 {
		resource := parts[i]
		if _, ok := specs[resource]; !ok && resource != "members" {
			return route{}, false
		}
		if resource == "members" && (i != 3 || len(parts) > 5) {
			return route{}, false
		}
		result.resource, result.id = resource, ""
		if i+1 < len(parts) {
			result.id = parts[i+1]
		}
		if i+2 < len(parts) {
			field := relation(resource, parts[i+2])
			if field == "" {
				return route{}, false
			}
			result.parents = append(result.parents, pathParent{resource, result.id, field})
		}
	}
	return result, true
}

func (p route) action(method string) (action, string) {
	if p.id == "" {
		switch method {
		case "GET":
			return read, ""
		case "POST":
			return create, ""
		default:
			return 0, "GET, POST"
		}
	}
	switch method {
	case "GET":
		return read, ""
	case "PUT", "PATCH":
		return update, ""
	case "DELETE":
		return remove, ""
	default:
		return 0, "GET, PUT, PATCH, DELETE"
	}
}

func (p route) parentsVisible(t *tenant, r role, userID string) bool {
	var previous *record
	for i, parent := range p.parents {
		item := t.Records[parent.resource][parent.id]
		if item == nil || !visible(r, userID, item) {
			return false
		}
		if previous != nil && item.Data[p.parents[i-1].field] != previous.ID {
			return false
		}
		previous = item
	}
	return true
}

func (p route) contains(item *record) bool {
	if len(p.parents) == 0 {
		return true
	}
	parent := p.parents[len(p.parents)-1]
	return item.Data[parent.field] == parent.id
}
