package rbac

import "testing"

// cell is an expected authorization result for a (resource, role) pair.
type cell struct {
	verbs     Verb
	ownerRead bool // viewer reads are owner-scoped
}

// TestPermissionMatrix verifies the exact public permission matrix, which is the
// source of truth for the whole service. Each cell is the set of verbs granted
// to a role on a resource. "None" means no verb.
func TestPermissionMatrix(t *testing.T) {
	const (
		none = VerbNone
		r    = VerbRead
		c    = VerbCreate
		u    = VerbUpdate
		d    = VerbDelete
	)
	crud := c | u | d | r
	cru := c | r | u
	ru := r | u
	rc := r | c

	// expected[resource][role] = allowed verb mask plus owner-scoping flag for
	// the viewer.
	//   R = VerbRead, C = VerbCreate, U = VerbUpdate, D = VerbDelete
	expect := map[string]map[Role]cell{
		"products": {
			RoleAdmin:   {crud, false},
			RoleManager: {cru, false},
			RoleViewer:  {r, false},
		},
		"prices": {
			RoleAdmin:   {crud, false},
			RoleManager: {ru, false},
			RoleViewer:  {r, false},
		},
		"orders": {
			RoleAdmin:   {crud, false},
			RoleManager: {cru, false},
			RoleViewer:  {r, true},
		},
		"customers": {
			RoleAdmin:   {crud, false},
			RoleManager: {ru, false},
			RoleViewer:  {none, false},
		},
		"invoices": {
			RoleAdmin:   {crud, false},
			RoleManager: {rc, false},
			RoleViewer:  {r, true},
		},
		"payments": {
			RoleAdmin:   {crud, false},
			RoleManager: {r, false},
			RoleViewer:  {none, false},
		},
		"refunds": {
			RoleAdmin:   {crud, false},
			RoleManager: {rc, false},
			RoleViewer:  {none, false},
		},
		"inventory": {
			RoleAdmin:   {crud, false},
			RoleManager: {ru, false},
			RoleViewer:  {r, false},
		},
		"api-keys": {
			RoleAdmin:   {crud, false},
			RoleManager: {none, false},
			RoleViewer:  {none, false},
		},
		"audit-logs": {
			RoleAdmin:   {r, false},
			RoleManager: {r, false},
			RoleViewer:  {none, false},
		},
	}

	if len(expect) != len(knownResources) {
		t.Fatalf("expected %d resources, got %d", len(knownResources), len(expect))
	}

	verbs := []Verb{VerbRead, VerbCreate, VerbUpdate, VerbDelete}
	for _, resource := range knownResources {
		roles, ok := expect[resource]
		if !ok {
			t.Errorf("resource %q missing from test table", resource)
			continue
		}
		for role, want := range roles {
			for _, v := range verbs {
				allow, ownerOnly := canAccess(resource, role, v)
				expected := want.verbs.Allows(v)
				if allow != expected {
					t.Errorf("canAccess(%q, %s, verb=%d) allow=%v want %v",
						resource, role.Name(), v, allow, expected)
					continue
				}
				// Owner-scoping should only matter for viewer reads on the
				// owner-restricted resources.
				if allow && role == RoleViewer {
					if want.ownerRead && !ownerOnly {
						t.Errorf("canAccess(%q, viewer, read): expected ownerOnly=true but got false", resource)
					}
					if !want.ownerRead && ownerOnly {
						t.Errorf("canAccess(%q, viewer, read): expected ownerOnly=false but got true", resource)
					}
				}
			}
		}
	}
}

// TestAuditLogsReadOnly confirms no role can create/update/delete audit logs.
func TestAuditLogsReadOnly(t *testing.T) {
	for _, role := range []Role{RoleAdmin, RoleManager, RoleViewer} {
		if allow, _ := canAccess("audit-logs", role, VerbCreate); allow {
			t.Errorf("audit-logs create must be denied for %s", role.Name())
		}
		if allow, _ := canAccess("audit-logs", role, VerbUpdate); allow {
			t.Errorf("audit-logs update must be denied for %s", role.Name())
		}
		if allow, _ := canAccess("audit-logs", role, VerbDelete); allow {
			t.Errorf("audit-logs delete must be denied for %s", role.Name())
		}
	}
	// But read roles should read.
	if allow, _ := canAccess("audit-logs", RoleAdmin, VerbRead); !allow {
		t.Error("admin must read audit-logs")
	}
	if allow, _ := canAccess("audit-logs", RoleManager, VerbRead); !allow {
		t.Error("manager must read audit-logs")
	}
	if allow, _ := canAccess("audit-logs", RoleViewer, VerbRead); allow {
		t.Error("viewer must NOT read audit-logs")
	}
}

// TestDefaultDenyAndUnknownResource ensures anything not in the table is denied.
func TestDefaultDenyAndUnknownResource(t *testing.T) {
	if allow, _ := canAccess("nonexistent-resource", RoleAdmin, VerbRead); allow {
		t.Error("unknown resource must be denied even for admin (default deny)")
	}
	if allow, _ := canAccess("products", RoleNone, VerbRead); allow {
		t.Error("RoleNone must never be granted")
	}
}

// TestUnionVerbsForMethodNotAllowed checks 405 detection.
func TestUnionVerbsForMethodNotAllowed(t *testing.T) {
	// audit-logs supports only reads.
	if verbs, ok := unionVerbs("audit-logs"); !ok || verbs.Allows(VerbDelete) {
		t.Errorf("audit-logs union should not include delete; got ok=%v verbs=%d", ok, verbs)
	}
	// products supports all verbs.
	ver, ok := unionVerbs("products")
	if !ok || !ver.Allows(VerbDelete) {
		t.Errorf("products union should include delete")
	}
	// unknown resource.
	if _, ok := unionVerbs("does-not-exist"); ok {
		t.Error("unknown resource union should be not-ok")
	}
}
