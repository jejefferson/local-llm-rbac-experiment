package rbac

import "testing"

func TestPolicyDefaultsToDeny(t *testing.T) {
	for _, r := range []role{"", "owner", "superadmin", admin, manager, viewer} {
		for _, a := range []action{0, read, create, update, remove, 128} {
			if allowed(r, "unknown-resource", a) {
				t.Errorf("unknown resource allowed for role %q, action %d", r, a)
			}
			if r != admin && r != manager && r != viewer && allowed(r, "products", a) {
				t.Errorf("unknown role %q allowed action %d", r, a)
			}
		}
	}
	if allowed(admin, "products", 0) || allowed(manager, "products", read|remove) {
		t.Fatal("zero or partially permitted action was allowed")
	}
}

func TestOwnershipVisibility(t *testing.T) {
	for _, resource := range []string{"orders", "invoices"} {
		item := &record{Resource: resource, OwnerID: "owner"}
		if !visible(viewer, "owner", item) || visible(viewer, "other", item) {
			t.Errorf("incorrect viewer ownership policy for %s", resource)
		}
		if !visible(admin, "other", item) || !visible(manager, "other", item) {
			t.Errorf("incorrect staff visibility for %s", resource)
		}
	}
	if visible(viewer, "owner", &record{Resource: "customers", OwnerID: "owner"}) {
		t.Fatal("ownership bypassed the resource permission policy")
	}
}
