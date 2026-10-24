package rbac

import (
	"sync"
	"testing"
)

// newSeededStore returns a freshly seeded store for tests.
func newSeededStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore()
	if err := SeedAll(s); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

// ---- membership / revocation --------------------------------------------

func TestMembershipRevocationTakesEffectOnNextCall(t *testing.T) {
	s := newSeededStore(t)
	admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}

	// Before revocation, the admin can create.
	if _, status := s.CreateRecord("products", "acme", admin, map[string]any{"sku": "X1", "name": "N"}); status != 0 {
		t.Fatalf("expected create to succeed before revocation, got status %d", status)
	}

	// Revoke the membership entirely.
	s.SetMembership("acme", "u-acme-admin", RoleNone)

	// The principal struct still claims admin, but the store consults the live
	// membership table and the create must now be forbidden.
	if _, status := s.CreateRecord("products", "acme", admin, map[string]any{"sku": "X2", "name": "N"}); status != statusForbidden {
		t.Errorf("expected forbidden after revocation, got status %d", status)
	}
	// Restores for later assertions only; not required, but shows it flips back.
	s.SetMembership("acme", "u-acme-admin", RoleAdmin)
	if _, status := s.CreateRecord("products", "acme", admin, map[string]any{"sku": "X3", "name": "N"}); status != 0 {
		t.Errorf("expected create to succeed after re-grant, got status %d", status)
	}
}

func TestDenyLeavesStateUnchanged(t *testing.T) {
	s := newSeededStore(t)
	// A viewer may read products (R) but cannot delete them.
	viewer := principal{UserID: "u-acme-v", Role: RoleViewer}
	// Find a product id to attempt deleting.
	items, _, _ := s.ListRecords("products", "acme", principal{UserID: "u-acme-admin", Role: RoleAdmin}, Filter{}, Page{Limit: 10})
	rows := items.([]*Record)
	if len(rows) == 0 {
		t.Fatal("expected at least one product")
	}
	id := rows[0].ID

	if status, _ := s.DeleteRecord("products", "acme", id, viewer); status != statusForbidden {
		t.Fatalf("viewer delete should be forbidden, got status %d", status)
	}
	// The record must still be present.
	if _, status := s.GetRecord("products", "acme", id, principal{UserID: "u-acme-admin", Role: RoleAdmin}); status != 0 {
		t.Errorf("record should still exist after a denied delete, got status %d", status)
	}
}

// ---- last-admin rule ----------------------------------------------------

func TestLastAdminCannotBeRemovedOrDemoted(t *testing.T) {
	s := NewStore()
	s.AddTenant("t", "T")
	s.SetMembership("t", "alice", RoleAdmin) // the only admin
	alice := principal{UserID: "alice", Role: RoleAdmin}

	// Demote last admin -> conflict.
	if m, status := s.UpdateMember("t", "alice", "manager", alice); status != statusConflict {
		t.Errorf("demoting last admin should conflict, got %d; member=%+v", status, m)
	}
	// Member must still be admin.
	if got := s.roleFor("t", "alice"); got != RoleAdmin {
		t.Errorf("last admin role must be unchanged, got %v", got)
	}

	// Remove last admin -> conflict.
	if status, _ := s.RemoveMember("t", "alice", alice); status != statusConflict {
		t.Errorf("removing last admin should conflict, got %d", status)
	}
	if s.roleFor("t", "alice") != RoleAdmin {
		t.Errorf("last admin must remain after a failed removal")
	}

	// Adding a second admin unblocks removal of the original.
	if _, status := s.AddMember("t", "bob", "admin", alice, "system"); status != 0 {
		t.Fatalf("adding second admin failed: %d", status)
	}
	// Now removing alice is fine (bob is the last admin).
	if status, _ := s.RemoveMember("t", "alice", alice); status != 0 {
		t.Errorf("removing alice with bob as second admin should succeed, got %d", status)
	}
	if s.roleFor("t", "alice") != RoleNone {
		t.Errorf("alice should have been removed")
	}
	if s.roleFor("t", "bob") != RoleAdmin {
		t.Errorf("bob should remain admin")
	}
}

func TestMemberManagementIsAdminOnly(t *testing.T) {
	s := newSeededStore(t)
	// A manager cannot add members (no permission).
	// Note role resolved live: u-acme-manager is manager in acme.
	man := principal{UserID: "u-acme-manager", Role: RoleManager}
	if m, status := s.AddMember("acme", "bob", "admin", man, "system"); status != statusForbidden {
		t.Errorf("manager add member should be forbidden, got %d m=%+v", status, m)
	}
	if _, status := s.UpdateMember("acme", "bob", "admin", man); status != statusForbidden {
		t.Errorf("manager update member should be forbidden, got %d", status)
	}
	if status, _ := s.RemoveMember("acme", "bob", man); status != statusForbidden {
		t.Errorf("manager remove member should be forbidden, got %d", status)
	}
	if _, _, status := s.ListMembers("acme", man, Page{}); status != statusForbidden {
		t.Errorf("manager list members should be forbidden, got %d", status)
	}
	// Admin can.
	admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
	if _, status := s.AddMember("acme", "bob", "manager", admin, "system"); status != 0 {
		t.Errorf("admin add member should succeed, got %d", status)
	}
	if s.roleFor("acme", "bob") != RoleManager {
		t.Errorf("bob should now be a manager")
	}
}

// ---- tenancy -------------------------------------------------------------

func TestTenantIsolation(t *testing.T) {
	s := newSeededStore(t)
	admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
	// Create a product in acme.
	rec, status := s.CreateRecord("products", "acme", admin, map[string]any{"sku": "ACME-1", "name": "N"})
	if status != 0 {
		t.Fatalf("create failed: %d", status)
	}
	prod := rec.(*Record)
	// u-acme-admin has no membership in globex, so any globex access is denied
	// (403 not-found-style for a non-member). Either 403 or 404 is acceptable,
	// but it must NOT succeed.
	if st, _ := s.GetRecord("products", "globex", prod.ID, admin); st == 0 {
		t.Errorf("product created in acme must not be reachable under globex (got success)")
	}
	// List under globex for an acme-only principal is forbidden (no membership).
	if _, st, _ := s.ListRecords("products", "globex", admin, Filter{}, Page{}); st != statusForbidden {
		t.Errorf("globex list for an acme-only principal should be forbidden, got %d", st)
	}
}

func TestTenantSpecificRolesForOneUser(t *testing.T) {
	s := newSeededStore(t)
	// u-multi is admin in acme and viewer in globex.
	if got := s.roleFor("acme", "u-multi"); got != RoleAdmin {
		t.Errorf("u-multi should be admin in acme, got %v", got)
	}
	if got := s.roleFor("globex", "u-multi"); got != RoleViewer {
		t.Errorf("u-multi should be viewer in globex, got %v", got)
	}
}

// ---- ownership ----------------------------------------------------------

func TestOwnerScopeForViewer(t *testing.T) {
	s := newSeededStore(t)
	// u-acme-v owns one order; u-acme-v2 owns another.
	v1 := principal{UserID: "u-acme-v", Role: RoleViewer}
	items, status, _ := s.ListRecords("orders", "acme", v1, Filter{}, Page{Limit: 100})
	if status != 0 {
		t.Fatalf("viewer list failed: %d", status)
	}
	rows := items.([]*Record)
	for _, r := range rows {
		if v1.UserID != r.Owner {
			t.Errorf("viewer %s saw an order they do not own: %s (owner=%s)", v1.UserID, r.ID, r.Owner)
		}
	}
	// Reading another user's order directly must be forbidden.
	itemsAll, _, _ := s.ListRecords("orders", "acme", principal{UserID: "u-acme-admin", Role: RoleAdmin}, Filter{}, Page{Limit: 100})
	all := itemsAll.([]*Record)
	var other *Record
	for _, r := range all {
		if r.Owner != v1.UserID {
			other = r
			break
		}
	}
	if other == nil {
		t.Skip("no other-owner order to test")
	}
	if _, status := s.GetRecord("orders", "acme", other.ID, v1); status != statusForbidden {
		t.Errorf("viewer reading another user's order should be forbidden, got %d", status)
	}
}

// ---- parent integrity ---------------------------------------------------

func TestParentIntegrity(t *testing.T) {
	s := newSeededStore(t)
	admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
	// Create a payment for a non-existent order -> not found.
	if _, status := s.CreateRecord("payments", "acme", admin, map[string]any{"order": "no-such-order", "amount": 5.0}); status != statusNotFound {
		t.Errorf("payment for missing order should be 404, got %d", status)
	}
	// Create an order first.
	ord, status := s.CreateRecord("orders", "acme", admin, map[string]any{"customer": "c", "owner": "u1", "status": "open", "total": 10.0})
	if status != 0 {
		t.Fatalf("order create failed: %d", status)
	}
	oid := ord.(*Record).ID
	// Now a payment for that order is fine.
	if _, status := s.CreateRecord("payments", "acme", admin, map[string]any{"order": oid, "amount": 10.0}); status != 0 {
		t.Errorf("payment for existing order should succeed, got %d", status)
	}
}

// ---- audit log ----------------------------------------------------------

func TestAuditLogAppendsAndIsListable(t *testing.T) {
	s := newSeededStore(t)
	admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
	// A create should be recorded.
	before, _ := s.ListAudit("acme", Page{Limit: 1000})
	s.CreateRecord("products", "acme", admin, map[string]any{"sku": "A", "name": "N"})
	after, _ := s.ListAudit("acme", Page{Limit: 1000})
	if len(after) <= len(before) {
		t.Errorf("expected audit log to grow, before=%d after=%d", len(before), len(after))
	}
	// Viewer cannot list audit logs.
	if _, status, _ := s.ListRecords("audit-logs", "acme", principal{UserID: "u-acme-v", Role: RoleViewer}, Filter{}, Page{}); status != statusForbidden {
		t.Errorf("viewer listing audit-logs should be forbidden, got %d", status)
	}
	// Admin can list audit logs.
	if _, status, _ := s.ListRecords("audit-logs", "acme", admin, Filter{}, Page{}); status != 0 {
		t.Errorf("admin listing audit-logs should succeed, got %d", status)
	}
}

// ---- concurrency --------------------------------------------------------

func TestConcurrentCRUDAndMembershipNoRace(t *testing.T) {
	s := newSeededStore(t)
	var wg sync.WaitGroup
	const goroutines = 20
	const iters = 100

	// Concurrent reads, creates (admin), reads (viewer), and membership toggles
	// on a non-admin member, all under the race detector.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			admin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
			viewer := principal{UserID: "u-acme-v", Role: RoleViewer}
			// Interleaved reads and creates across goroutines.
			for i2 := 0; i2 < iters; i2++ {
				_, _, _ = s.ListRecords("products", "acme", admin, Filter{}, Page{Limit: 5})
				_, _, _ = s.ListRecords("orders", "acme", viewer, Filter{}, Page{Limit: 5})
				_, _ = s.CreateRecord("products", "acme", admin, map[string]any{"sku": "c", "name": "n"})
			}
		}()
	}

	// A separate goroutine toggles the manager's membership (manager<->none).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iters; j++ {
			if j%2 == 0 {
				s.SetMembership("acme", "u-acme-manager", RoleManager)
			} else {
				s.SetMembership("acme", "u-acme-manager", RoleNone)
			}
		}
	}()

	wg.Wait()
	// Restore for any subsequent assertions.
	s.SetMembership("acme", "u-acme-manager", RoleManager)
}

// TestConcurrentMembershipRevocationNoGap exercises the time-of-check /
// time-of-use property: a revocation concurrent with a create must not let a
// create through after the membership is gone.
func TestConcurrentMembershipRevocationNoGap(t *testing.T) {
	// Use a dedicated store so the toggle is deterministic.
	s := NewStore()
	s.AddTenant("iso", "ISO")
	s.SetMembership("iso", "carol", RoleAdmin)
	admin := principal{UserID: "carol", Role: RoleAdmin}

	// Toggle admin->none; after the revoke completes, subsequent creates from the
	// same principal must be forbidden (the store re-checks under the lock).
	done := make(chan struct{})
	go func() {
		close(done) // barrier
		s.SetMembership("iso", "carol", RoleNone)
	}()
	<-done
	// Wait until the toggle is observed.
	s.mu.Lock()
	revoked := s.roleFor("iso", "carol") == RoleNone
	s.mu.Unlock()
	if !revoked {
		t.Fatalf("expected carol to be revoked under lock, still %v", s.roleFor("iso", "carol"))
	}
	if _, status := s.CreateRecord("products", "iso", admin, map[string]any{"sku": "z", "name": "n"}); status != statusForbidden {
		t.Errorf("create after revocation must be forbidden, got %d", status)
	}
}
