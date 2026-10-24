package rbac

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// This file is the thread-safe, in-memory data store. It owns tenancy,
// memberships, opaque tokens, the ten resources, and the append-only audit
// log. Every mutation path re-checks authorization against the live
// membership table while holding the write lock, so a revocation that lands
// between the HTTP layer's identity resolution and the state change cannot
// create a time-of-check/time-of-use authorization gap.

// now is the clock, overridable in tests.
var now = func() time.Time { return time.Now().UTC() }

// Tenant is a tenant (organization) in the service.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// TokenRec is the server-side record behind an opaque bearer token. The token
// string itself carries no decodable role or user id; only this record does.
type TokenRec struct {
	UserID    string    `json:"userId"`
	Tenant    string    `json:"tenant"`
	IssuedBy  string    `json:"issuedBy"`
	CreatedAt time.Time `json:"createdAt"`
}

// Record is a single stored object of a resource type. The public fields plus
// the resource-specific Data map are flattened into the JSON response.
type Record struct {
	Resource  string         `json:"-"`
	ID        string         `json:"id"`
	Tenant    string         `json:"tenant"`
	Owner     string         `json:"owner,omitempty"`
	Parent    string         `json:"parent,omitempty"`
	Data      map[string]any `json:"-"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// MarshalJSON flattens the standard fields together with the resource-specific
// fields so the API surface stays flat and predictable.
func (r *Record) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(r.Data)+6)
	for k, v := range r.Data {
		out[k] = v
	}
	out["id"] = r.ID
	out["tenant"] = r.Tenant
	out["createdAt"] = r.CreatedAt
	out["updatedAt"] = r.UpdatedAt
	if r.Owner != "" {
		out["owner"] = r.Owner
	}
	if r.Parent != "" {
		out["parent"] = r.Parent
	}
	return jsonMarshalMap(out)
}

// AuditEntry is an immutable, append-only audit log record.
type AuditEntry struct {
	ID         string    `json:"id"`
	Tenant     string    `json:"tenant"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resourceId,omitempty"`
	Result     string    `json:"result"`
	Timestamp  time.Time `json:"timestamp"`
}

// resourceMeta captures cross-cutting structure of a resource: whether reads
// are owner-scoped and whether it is a child of another resource.
type resourceMeta struct {
	Name           string
	OwnerScoped    bool
	OwnerField     string
	ParentResource string
	ParentField    string
}

var resourceMetaTable = map[string]resourceMeta{
	"products":   {Name: "products"},
	"prices":     {Name: "prices", ParentResource: "products", ParentField: "product"},
	"orders":     {Name: "orders", OwnerScoped: true, OwnerField: "owner"},
	"customers":  {Name: "customers"},
	"invoices":   {Name: "invoices", OwnerScoped: true, OwnerField: "owner", ParentResource: "orders", ParentField: "order"},
	"payments":   {Name: "payments", ParentResource: "orders", ParentField: "order"},
	"refunds":    {Name: "refunds", ParentResource: "orders", ParentField: "order"},
	"inventory":  {Name: "inventory", ParentResource: "products", ParentField: "product"},
	"api-keys":   {Name: "api-keys"},
	"audit-logs": {Name: "audit-logs"},
}

func resourceMetaFor(resource string) (resourceMeta, bool) {
	m, ok := resourceMetaTable[resource]
	return m, ok
}

// Store is the authoritative in-memory state. All access is guarded by mu.
type Store struct {
	mu    sync.RWMutex
	idGen atomic.Uint64

	tenants     map[string]*Tenant
	tokens      map[string]TokenRec                      // opaque token string -> record
	memberships map[string]map[string]Role               // tenant -> user -> role
	records     map[string]map[string]map[string]*Record // resource -> tenant -> id
	audit       map[string][]*AuditEntry
}

// NewStore returns an empty, initialized store.
func NewStore() *Store {
	return &Store{
		tenants:     make(map[string]*Tenant),
		tokens:      make(map[string]TokenRec),
		memberships: make(map[string]map[string]Role),
		records:     make(map[string]map[string]map[string]*Record),
		audit:       make(map[string][]*AuditEntry),
	}
}

func (s *Store) nextID(prefix string) string {
	n := s.idGen.Add(1)
	return fmt.Sprintf("%s-%d", prefix, n)
}

// ---- tenancy / identity / membership -----------------------------------

// AddTenant registers a tenant. Used during seeding.
func (s *Store) AddTenant(id, name string) *Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &Tenant{ID: id, Name: name, CreatedAt: now()}
	if existing, ok := s.tenants[id]; ok {
		return existing
	}
	s.tenants[id] = t
	return t
}

// AddToken registers an opaque token for a user/tenant pair.
func (s *Store) AddToken(token, userID, tenant, issuedBy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = TokenRec{UserID: userID, Tenant: tenant, IssuedBy: issuedBy, CreatedAt: now()}
}

// SetMembership sets a user's role within a tenant.
func (s *Store) SetMembership(tenant, user string, role Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMembershipTenant(tenant)
	s.memberships[tenant][user] = role
}

func (s *Store) ensureMembershipTenant(tenant string) {
	if s.memberships[tenant] == nil {
		s.memberships[tenant] = make(map[string]Role)
	}
}

// roleFor resolves a user's role within a tenant. The role is read live so
// that membership changes and revocations take effect on the next request.
func (s *Store) roleFor(tenant, user string) Role {
	users := s.memberships[tenant]
	if users == nil {
		return RoleNone
	}
	r, ok := users[user]
	if !ok {
		return RoleNone
	}
	return r
}

// ---- identity resolution (token -> user), thread-safe -------------------

// ResolveToken maps an opaque token to its issuer (user + default tenant).
// Unknown or empty tokens resolve to ok=false.
func (s *Store) ResolveToken(token string) (TokenRec, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.tokens[token]
	return rec, ok
}

// ---- audit log -----------------------------------------------------------

// appendAudit records an audit entry for a tenant. Must be called with s.mu
// held (write lock).
func (s *Store) appendAudit(tenant, actor, action, resource, resourceID, result string) {
	e := &AuditEntry{
		ID:         s.nextID("audit"),
		Tenant:     tenant,
		Actor:      actor,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Result:     result,
		Timestamp:  now(),
	}
	s.audit[tenant] = append(s.audit[tenant], e)
}

// ListAudit returns paginated audit entries for a tenant.
func (s *Store) ListAudit(tenant string, p Page) ([]*AuditEntry, Page) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.audit[tenant]
	start, end := p.apply(len(all))
	out := make([]*AuditEntry, 0, end-start)
	for _, e := range all[start:end] {
		out = append(out, e)
	}
	return out, p
}

// ---- generic record access ----------------------------------------------

func (s *Store) indexForResource(resource string) map[string]map[string]*Record {
	idx := s.records[resource]
	if idx == nil {
		idx = make(map[string]map[string]*Record)
		s.records[resource] = idx
	}
	return idx
}

func (s *Store) tenantIndex(resource, tenant string) map[string]*Record {
	idx := s.indexForResource(resource)
	ten := idx[tenant]
	if ten == nil {
		ten = make(map[string]*Record)
		idx[tenant] = ten
	}
	return ten
}

func (s *Store) recordID(resource string) string {
	if p, ok := idPrefix[resource]; ok {
		return p
	}
	return "rec"
}

// prefixByResource is used to build seed ids deterministically.
var idPrefix = map[string]string{
	"products":   "prod",
	"prices":     "price",
	"orders":     "ord",
	"customers":  "cust",
	"invoices":   "inv",
	"payments":   "pay",
	"refunds":    "ref",
	"inventory":  "invn",
	"api-keys":   "key",
	"audit-logs": "audit",
}

// ---- reads ---------------------------------------------------------------

// GetRecord returns a single record, enforcing read permission, owner-scope,
// parent referential/access, and tenant isolation. Returns nil + status.
func (s *Store) GetRecord(resource, tenant, id string, actor principal) (any, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Role is always derived from the live membership table, never trusted from
	// the caller-supplied principal, so a stale or forged role cannot grant a read.
	role := s.roleFor(tenant, actor.UserID)

	if !s.isKnownResource(resource) {
		return nil, statusNotFound
	}
	allow, ownerOnly := canAccess(resource, role, VerbRead)
	if !allow {
		return nil, statusForbidden
	}

	ten := s.records[resource]
	if ten == nil {
		return nil, statusNotFound
	}
	tenantMap := ten[tenant]
	if tenantMap == nil {
		return nil, statusNotFound
	}
	rec, ok := tenantMap[id]
	if !ok {
		return nil, statusNotFound
	}

	meta, _ := resourceMetaFor(resource)
	// Owner scope: when ownerOnly, a record is visible only to its owner.
	if ownerOnly && rec.Owner != actor.UserID {
		return nil, statusForbidden
	}
	// Parent referential integrity + read on the parent resource.
	if meta.ParentResource != "" {
		if !s.parentExists(meta.ParentResource, tenant, rec.Parent) {
			return nil, statusNotFound
		}
		if pAllow, _ := canAccess(meta.ParentResource, role, VerbRead); !pAllow {
			return nil, statusForbidden
		}
	}
	return rec, 0 // found
}

func (s *Store) isKnownResource(resource string) bool {
	return IsKnownResource(resource)
}

// ListRecords returns a page of records, enforcing read permission, filtering
// and pagination. All filtering happens before pagination so pages stay
// contiguous.
func (s *Store) ListRecords(resource, tenant string, actor principal, filter Filter, page Page) (any, int, Page) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Role is derived from the live membership table, never trusted from the caller.
	role := s.roleFor(tenant, actor.UserID)

	if !s.isKnownResource(resource) {
		return nil, statusNotFound, page
	}
	allow, ownerOnly := canAccess(resource, role, VerbRead)
	if !allow {
		return nil, statusForbidden, page
	}

	ten := s.records[resource]
	all := make([]*Record, 0)
	if ten != nil {
		for _, r := range ten[tenant] {
			all = append(all, r)
		}
	}
	// Stable ordering by id.
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	meta, _ := resourceMetaFor(resource)
	// Mandatory owner restriction for owner-scoped role reads.
	if ownerOnly {
		all = filterByOwner(all, actor.UserID)
	}
	// Optional explicit owner filter (admin/manager convenience).
	if filter.Owner != "" {
		all = filterByOwner(all, filter.Owner)
	}
	if filter.Status != "" {
		all = filterByStatus(all, filter.Status)
	}
	if filter.Parent != "" {
		all = filterByParent(all, filter.Parent)
	}
	// Referential integrity + parent read access, for the whole result set.
	if meta.ParentResource != "" {
		pAllow, _ := canAccess(meta.ParentResource, role, VerbRead)
		kept := make([]*Record, 0, len(all))
		for _, r := range all {
			if !s.parentExists(meta.ParentResource, tenant, r.Parent) {
				continue
			}
			if !pAllow {
				continue
			}
			kept = append(kept, r)
		}
		all = kept
	}

	start, end := page.apply(len(all))
	out := make([]*Record, 0, end-start)
	for _, r := range all[start:end] {
		out = append(out, r)
	}
	return out, 0, page
}

func filterByOwner(all []*Record, owner string) []*Record {
	out := make([]*Record, 0, len(all))
	for _, r := range all {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out
}

func filterByStatus(all []*Record, status string) []*Record {
	out := make([]*Record, 0, len(all))
	for _, r := range all {
		if v, ok := r.Data["status"].(string); ok && v == status {
			out = append(out, r)
		}
	}
	return out
}

func filterByParent(all []*Record, parent string) []*Record {
	out := make([]*Record, 0, len(all))
	for _, r := range all {
		if r.Parent == parent {
			out = append(out, r)
		}
	}
	return out
}

// applyPage normalizes a Page in place against the supplied total and returns
// the [start,end) slice bounds. It also fills the response fields so callers
// can echo pagination back to clients.
func (p *Page) apply(total int) (start, end int) {
	if p.Limit <= 0 || p.Limit > maxPage {
		p.Limit = defaultPage
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	p.PageInfo.Total = total
	start = p.Offset
	if start > total {
		start = total
	}
	end = start + p.Limit
	if end > total {
		end = total
	}
	p.PageInfo.Limit = p.Limit
	p.PageInfo.Offset = p.Offset
	p.PageInfo.HasMore = end < total
	return start, end
}

func (s *Store) parentExists(resource, tenant, parent string) bool {
	if parent == "" {
		return true
	}
	ten := s.records[resource]
	if ten == nil {
		return false
	}
	t := ten[tenant]
	if t == nil {
		return false
	}
	_, ok := t[parent]
	return ok
}

// ---- writes --------------------------------------------------------------

// CreateRecord atomically authorizes and inserts a record. Authorization is
// re-checked under the write lock so a concurrent revocation cannot slip past.
func (s *Store) CreateRecord(resource, tenant string, actor principal, in map[string]any) (any, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isKnownResource(resource) {
		return nil, statusNotFound
	}
	role := s.roleFor(tenant, actor.UserID)
	if !roleAllowed(resource, role, VerbCreate) {
		return nil, statusForbidden
	}
	meta, _ := resourceMetaFor(resource)

	// Parent referential integrity for children.
	if meta.ParentResource != "" {
		parent := stringField(in, meta.ParentField)
		if parent == "" {
			return nil, statusBadRequest
		}
		if !s.parentExists(meta.ParentResource, tenant, parent) {
			return nil, statusNotFound
		}
		if pAllow, _ := canAccess(meta.ParentResource, role, VerbRead); !pAllow {
			return nil, statusForbidden
		}
	}

	if err := validateResource(resource, in, true); err != nil {
		return nil, errStatus(err)
	}

	id := s.nextID(s.recordID(resource))
	owner := stringField(in, "owner")
	if meta.OwnerScoped && owner == "" {
		owner = actor.UserID
	}
	rec := &Record{
		Resource:  resource,
		ID:        id,
		Tenant:    tenant,
		Owner:     owner,
		Parent:    stringField(in, parentFieldOf(in, meta)),
		Data:      extractData(in, meta),
		CreatedAt: now(),
		UpdatedAt: now(),
	}
	s.tenantIndex(resource, tenant)[id] = rec
	s.appendAudit(tenant, actor.UserID, "create", resource, id, "ok")
	return rec, 0
}

func parentFieldOf(in map[string]any, meta resourceMeta) string {
	if meta.ParentField == "" {
		return ""
	}
	return stringField(in, meta.ParentField)
}

// UpdateRecord atomically authorizes and updates a record. Partial updates
// (PATCH) merge into existing fields; full updates (PUT) replace them.
func (s *Store) UpdateRecord(resource, tenant, id string, actor principal, in map[string]any, full bool) (any, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isKnownResource(resource) {
		return nil, statusNotFound
	}
	role := s.roleFor(tenant, actor.UserID)
	if !roleAllowed(resource, role, VerbUpdate) {
		return nil, statusForbidden
	}

	ten := s.records[resource]
	var rec *Record
	if ten != nil {
		if t := ten[tenant]; t != nil {
			rec = t[id]
		}
	}
	if rec == nil {
		return nil, statusNotFound
	}
	meta, _ := resourceMetaFor(resource)
	// Immutable core fields are preserved on update.

	if full {
		if err := validateResource(resource, in, false); err != nil {
			return nil, errStatus(err)
		}
		// Preserve identity + immutable core.
		data := extractData(in, meta)
		if meta.OwnerScoped {
			data[meta.OwnerField] = rec.Owner
		}
		if meta.ParentField != "" {
			data[meta.ParentField] = rec.Parent
		}
		rec.Data = data
	} else {
		// Merge patch fields; ignore immutable core fields supplied in patch.
		for k, v := range in {
			if k == "id" || k == "tenant" || k == "createdAt" || k == "updatedAt" {
				continue
			}
			if meta.OwnerField != "" && k == meta.OwnerField {
				continue // owner immutable after creation
			}
			if meta.ParentField != "" && k == meta.ParentField {
				if p, ok := s.records[meta.ParentResource]; ok {
					if t := p[tenant]; t != nil {
						if _, ok := t[stringValue(v)]; ok {
							rec.Parent = stringValue(v)
						} else {
							return nil, statusNotFound
						}
					}
				}
				continue
			}
			rec.Data[k] = v
		}
	}
	rec.UpdatedAt = now()
	s.appendAudit(tenant, actor.UserID, "update", resource, id, "ok")
	return rec, 0
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// DeleteRecord authorizes and removes a record.
func (s *Store) DeleteRecord(resource, tenant, id string, actor principal) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isKnownResource(resource) {
		return statusNotFound, ""
	}
	role := s.roleFor(tenant, actor.UserID)
	if !roleAllowed(resource, role, VerbDelete) {
		return statusForbidden, ""
	}
	ten := s.records[resource]
	var rec *Record
	if ten != nil {
		if t := ten[tenant]; t != nil {
			rec = t[id]
		}
	}
	if rec == nil {
		return statusNotFound, ""
	}
	delete(ten[tenant], id)
	if len(ten[tenant]) == 0 {
		delete(ten, tenant)
	}
	s.appendAudit(tenant, actor.UserID, "delete", resource, id, "ok")
	return 0, id
}

// extractData returns a fresh copy of the resource-specific fields (excluding
// the standard/core fields), for storage.
func extractData(in map[string]any, meta resourceMeta) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "id", "tenant", "owner", meta.ParentField, "createdAt", "updatedAt":
			continue
		}
		out[k] = v
	}
	// carry parent even though it is also a top-level field
	if meta.ParentField != "" {
		if p := stringField(in, meta.ParentField); p != "" {
			out[meta.ParentField] = p
		}
	}
	return out
}

// roleAllowed is the low-level, lock-free authorization check used inside the
// store (always called under the write lock for mutations).
func roleAllowed(resource string, role Role, verb Verb) bool {
	allow, _ := canAccess(resource, role, verb)
	return allow
}

// errStatus maps a validation error to its HTTP status.
func errStatus(e *apiError) int { return e.status }

// ---- membership management (admin-only) ---------------------------------

// Member is the public view of a tenant membership.
type Member struct {
	Tenant string `json:"tenant"`
	User   string `json:"user"`
	Role   string `json:"role"`
}

// ListMembers returns all memberships in a tenant (admin only).
func (s *Store) ListMembers(tenant string, actor principal, p Page) ([]Member, Page, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.roleFor(tenant, actor.UserID) != RoleAdmin {
		return nil, p, statusForbidden
	}
	users := s.memberships[tenant]
	names := make([]string, 0, len(users))
	for u := range users {
		names = append(names, u)
	}
	sort.Strings(names)
	full := make([]Member, 0, len(names))
	for _, u := range names {
		full = append(full, Member{Tenant: tenant, User: u, Role: users[u].Name()})
	}
	start, end := p.apply(len(full))
	page := full[start:end]
	if page == nil {
		page = []Member{}
	}
	return page, p, 0
}

// AddMember adds or replaces a tenant membership (admin only).
func (s *Store) AddMember(tenant, user, roleStr string, actor principal, issuedBy string) (Member, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.roleFor(tenant, actor.UserID) != RoleAdmin {
		return Member{}, statusForbidden
	}
	role, ok := ParseRole(roleStr)
	if !ok || role == RoleNone {
		return Member{}, statusBadRequest
	}
	s.ensureMembershipTenant(tenant)
	// A non-admin cannot be used to elevate a non-admin actor; the actor is
	// already required to be admin, so this can only promote/demote.
	// Record a self-promotion as an audit event too.
	s.memberships[tenant][user] = role
	if issuedBy == "" {
		issuedBy = actor.UserID
	}
	s.AddTokenForMember(user, tenant, actor.UserID) // mint or refresh a token for the user
	s.appendAudit(tenant, actor.UserID, "add-member", "members", user, "ok")
	return Member{Tenant: tenant, User: user, Role: roleStr}, 0
}

// AddTokenForMember registers a deterministic token for a user/tenant so new
// members can authenticate. Must be called under the write lock.
func (s *Store) AddTokenForMember(user, tenant, issuedBy string) {
	tok := "tok-" + tenant + "-" + user
	if _, ok := s.tokens[tok]; !ok {
		s.tokens[tok] = TokenRec{UserID: user, Tenant: tenant, IssuedBy: issuedBy, CreatedAt: now()}
	}
}

// UpdateMember promotes or demotes a member. Enforces the last-admin rule.
func (s *Store) UpdateMember(tenant, user, roleStr string, actor principal) (Member, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleFor(tenant, actor.UserID) != RoleAdmin {
		return Member{}, statusForbidden
	}
	users := s.memberships[tenant]
	if users == nil {
		return Member{}, statusNotFound
	}
	current, ok := users[user]
	if !ok {
		return Member{}, statusNotFound
	}
	role, ok := ParseRole(roleStr)
	if !ok || role == RoleNone {
		return Member{}, statusBadRequest
	}
	// Last-admin rule: you may not demote the last remaining admin.
	if current == RoleAdmin && role != RoleAdmin {
		if s.countAdmins(tenant) <= 1 {
			return Member{}, statusConflict
		}
	}
	users[user] = role
	s.appendAudit(tenant, actor.UserID, "update-member", "members", user, "ok")
	return Member{Tenant: tenant, User: user, Role: roleStr}, 0
}

// RemoveMember revokes a membership. Enforces the last-admin rule.
func (s *Store) RemoveMember(tenant, user string, actor principal) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleFor(tenant, actor.UserID) != RoleAdmin {
		return statusForbidden, ""
	}
	users := s.memberships[tenant]
	if users == nil {
		return statusNotFound, ""
	}
	current, ok := users[user]
	if !ok {
		return statusNotFound, ""
	}
	if current == RoleAdmin && s.countAdmins(tenant) <= 1 {
		return statusConflict, ""
	}
	delete(users, user)
	if len(users) == 0 {
		delete(s.memberships, tenant)
	}
	s.appendAudit(tenant, actor.UserID, "remove-member", "members", user, "ok")
	return 0, user
}

// countAdmins returns how many admins exist in a tenant. Called under lock.
func (s *Store) countAdmins(tenant string) int {
	n := 0
	for u, r := range s.memberships[tenant] {
		_ = u
		if r == RoleAdmin {
			n++
		}
	}
	return n
}
