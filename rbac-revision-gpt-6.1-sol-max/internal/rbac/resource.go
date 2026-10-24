package rbac

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

func (s *Server) resource(t *tenant, path route, userID string, r role, a action, method, rawQuery string, body map[string]any, bodyError *apiError) response {
	var item *record
	if path.id != "" {
		item = t.Records[path.resource][path.id]
		if item == nil || !visible(r, userID, item) || !path.contains(item) {
			return failure(notFound("record not found"))
		}
	}
	if a == read {
		if item != nil {
			if rawQuery != "" {
				return failure(badInput("query parameters are only supported on lists"))
			}
			return response{status: 200, body: item.json()}
		}
		query, err := parseQuery(rawQuery, path.resource)
		if err != nil {
			return failure(err)
		}
		items := make([]map[string]any, 0)
		for _, candidate := range t.Records[path.resource] {
			if !visible(r, userID, candidate) || !path.contains(candidate) {
				continue
			}
			data := candidate.json()
			if query.matches(data) {
				items = append(items, data)
			}
		}
		return query.page(items)
	}
	if rawQuery != "" {
		return failure(badInput("query parameters are only supported on lists"))
	}
	if a == remove {
		if hasChildren(t, item) {
			return failure(conflict("dependent_records", "delete dependent records before deleting this record"))
		}
		delete(t.Records[path.resource], item.ID)
		s.store.audit(t, userID, "delete", path.resource, item.ID, nil)
		return response{status: 204}
	}
	if bodyError != nil {
		return failure(bodyError)
	}
	if len(path.parents) > 0 {
		parent := path.parents[len(path.parents)-1]
		if value, exists := body[parent.field]; exists && value != parent.id {
			return failure(badInput("foreign key does not match the parent path"))
		}
		body[parent.field] = parent.id
	}
	data, err := validateData(t, path.resource, body, item, method == "PUT")
	if err != nil {
		return failure(err)
	}
	if a == create {
		if path.resource == "api-keys" {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return failure(&apiError{500, "internal_error", "could not generate API key"})
			}
			data["key"] = "ak_" + base64.RawURLEncoding.EncodeToString(key)
		}
		now := time.Now().UTC()
		item = &record{
			ID: s.store.newID(path.resource), TenantID: t.ID, Resource: path.resource,
			CreatedAt: now, UpdatedAt: now, Data: data,
		}
		if path.resource == "orders" {
			item.OwnerID = userID
		} else if path.resource == "invoices" {
			item.OwnerID = t.Records["orders"][data["order_id"].(string)].OwnerID
		}
		t.Records[path.resource][item.ID] = item
		s.store.audit(t, userID, "create", path.resource, item.ID, nil)
		return response{status: 201, body: item.json(), headers: map[string]string{
			"Location": "/tenants/" + t.ID + "/" + path.resource + "/" + item.ID,
		}}
	}
	item.Data = data
	item.UpdatedAt = time.Now().UTC()
	s.store.audit(t, userID, "update", path.resource, item.ID, nil)
	return response{status: 200, body: item.json()}
}
