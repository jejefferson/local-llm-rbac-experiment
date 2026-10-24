package rbac

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"
)

//go:embed fixtures/seed.json
var seedJSON []byte

type seedUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

type seedTenant struct {
	ID      string                      `json:"id"`
	Name    string                      `json:"name"`
	Members map[string]role             `json:"members"`
	Records map[string][]map[string]any `json:"records"`
}

type fixture struct {
	Users   []seedUser   `json:"users"`
	Tenants []seedTenant `json:"tenants"`
}

// NewServer returns an independent API instance seeded from the public fixture.
// No files, environment variables, network services, or working directory are
// needed at runtime. Fixture API keys do not act as identity bearer tokens.
func NewServer() (*Server, error) {
	var seed fixture
	decoder := json.NewDecoder(bytes.NewReader(seedJSON))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seed); err != nil {
		return nil, fmt.Errorf("invalid seed JSON: %w", err)
	}
	s := &Server{
		store:      &store{tenants: make(map[string]*tenant), nextID: 1000},
		tokenUsers: make(map[string]string), users: make(map[string]bool),
	}
	for _, user := range seed.Users {
		if !validID(user.ID) || len(user.Token) < 32 || s.users[user.ID] || s.tokenUsers[user.Token] != "" {
			return nil, fmt.Errorf("invalid or duplicate seed identity: %s", user.ID)
		}
		s.users[user.ID] = true
		s.tokenUsers[user.Token] = user.ID
	}
	for _, source := range seed.Tenants {
		if !validID(source.ID) || s.store.tenants[source.ID] != nil {
			return nil, fmt.Errorf("invalid or duplicate seed tenant: %s", source.ID)
		}
		t := &tenant{ID: source.ID, Name: source.Name, Members: source.Members, Records: make(map[string]map[string]*record)}
		admins := 0
		for userID, r := range t.Members {
			if !s.users[userID] || !validRole(r) {
				return nil, fmt.Errorf("invalid seed membership: %s/%s", t.ID, userID)
			}
			if r == admin {
				admins++
			}
		}
		if admins == 0 {
			return nil, fmt.Errorf("seed tenant has no administrator: %s", t.ID)
		}
		for _, name := range resourceNames() {
			t.Records[name] = make(map[string]*record)
		}
		for resource, records := range source.Records {
			if _, ok := specs[resource]; !ok {
				return nil, fmt.Errorf("unknown seed resource: %s", resource)
			}
			for _, data := range records {
				id, _ := data["id"].(string)
				created, _ := data["created_at"].(string)
				createdAt, err := time.Parse(time.RFC3339Nano, created)
				if !validID(id) || t.Records[resource][id] != nil || err != nil {
					return nil, fmt.Errorf("invalid seed record: %s/%s/%s", t.ID, resource, id)
				}
				owner, _ := data["owner_id"].(string)
				if owner != "" && (!s.users[owner] || (resource != "orders" && resource != "invoices")) {
					return nil, fmt.Errorf("invalid seed owner: %s", id)
				}
				delete(data, "id")
				delete(data, "created_at")
				delete(data, "owner_id")
				t.Records[resource][id] = &record{
					ID: id, TenantID: t.ID, Resource: resource, OwnerID: owner,
					CreatedAt: createdAt, UpdatedAt: createdAt, Data: data,
				}
			}
		}
		s.store.tenants[t.ID] = t
	}
	// Validate all foreign keys after all records are present, independently of
	// JSON object iteration order.
	for _, t := range s.store.tenants {
		for resource, records := range t.Records {
			for _, item := range records {
				if resource == "audit-logs" {
					continue
				}
				input := clone(item.Data).(map[string]any)
				if resource == "api-keys" {
					key, ok := input["key"].(string)
					if !ok || len(key) < 32 {
						return nil, fmt.Errorf("invalid seed API key: %s", item.ID)
					}
					delete(input, "key")
				}
				data, err := validateData(t, resource, input, nil, false)
				if err != nil {
					return nil, fmt.Errorf("invalid seed record %s: %s", item.ID, err.Message)
				}
				if resource == "api-keys" {
					data["key"] = item.Data["key"]
				}
				if resource == "orders" && item.OwnerID == "" {
					return nil, fmt.Errorf("seed order missing owner: %s", item.ID)
				}
				if resource == "invoices" && item.OwnerID != t.Records["orders"][data["order_id"].(string)].OwnerID {
					return nil, fmt.Errorf("seed invoice has wrong owner: %s", item.ID)
				}
				item.Data = data
			}
		}
	}
	return s, nil
}
