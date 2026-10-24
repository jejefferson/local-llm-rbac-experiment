package rbac

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type record struct {
	ID        string
	TenantID  string
	Resource  string
	OwnerID   string
	CreatedAt time.Time
	UpdatedAt time.Time
	Data      map[string]any
}

type tenant struct {
	ID      string
	Name    string
	Members map[string]role
	Records map[string]map[string]*record
}

type store struct {
	// Every authorization check involving membership and the resulting operation
	// share this lock. A revocation cannot slip between a check and a write.
	mu      sync.RWMutex
	tenants map[string]*tenant
	nextID  uint64
}

func (s *store) newID(resource string) string {
	s.nextID++
	prefix := strings.TrimSuffix(resource, "s")
	return fmt.Sprintf("%s-%012d", prefix, s.nextID)
}

func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for key, item := range v {
			result[key] = clone(item)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = clone(item)
		}
		return result
	default:
		return value
	}
}

func (r *record) json() map[string]any {
	result := clone(r.Data).(map[string]any)
	result["id"] = r.ID
	result["tenant_id"] = r.TenantID
	result["created_at"] = r.CreatedAt.Format(time.RFC3339Nano)
	result["updated_at"] = r.UpdatedAt.Format(time.RFC3339Nano)
	if r.OwnerID != "" {
		result["owner_id"] = r.OwnerID
	}
	return result
}

func (s *store) audit(t *tenant, actor, operation, resource, id string, details map[string]any) {
	now := time.Now().UTC()
	entry := &record{
		ID: s.newID("audit-logs"), TenantID: t.ID, Resource: "audit-logs",
		CreatedAt: now, UpdatedAt: now,
		Data: map[string]any{
			"actor_id": actor, "action": operation, "resource": resource,
			"resource_id": id, "details": clone(details),
		},
	}
	t.Records["audit-logs"][entry.ID] = entry
}

func memberJSON(t *tenant, userID string) map[string]any {
	return map[string]any{"tenant_id": t.ID, "user_id": userID, "role": t.Members[userID]}
}
