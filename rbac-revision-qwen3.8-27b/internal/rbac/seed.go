package rbac

import "log"

// This file seeds a fixed, deterministic in-memory dataset used both by the
// program startup and by the black-box HTTP tests. It registers two tenants,
// three roles spread across users (including a tenant-specific role for a
// single user), opaque token fixtures, and a small baseline of each resource so
// the API is usable on start.

// TokenFor returns the deterministic opaque token fixture for a user/tenant pair.
// The token string itself is opaque to clients; only the store resolves it.
func TokenFor(user, tenant string) string {
	return "tok-" + tenant + "-" + user
}

// SeedAll populates a store with the public fixtures. It is idempotent enough
// for a single startup; it returns an error only on an internal inconsistency.
func SeedAll(s *Store) error {
	// --- tenants -----------------------------------------------------------
	s.AddTenant("acme", "Acme Corp")
	s.AddTenant("globex", "Globex Inc")

	// --- memberships (tenant-specific roles) ------------------------------
	// acme tenant
	s.SetMembership("acme", "u-acme-admin", RoleAdmin)
	s.SetMembership("acme", "u-acme-manager", RoleManager)
	s.SetMembership("acme", "u-acme-v", RoleViewer)
	s.SetMembership("acme", "u-acme-v2", RoleViewer)
	// one user with DIFFERENT roles in different tenants:
	s.SetMembership("acme", "u-multi", RoleAdmin)
	s.SetMembership("globex", "u-multi", RoleViewer)
	// globex tenant
	s.SetMembership("globex", "u-globex-admin", RoleAdmin)

	// --- opaque token fixtures --------------------------------------------
	s.AddToken(TokenFor("u-acme-admin", "acme"), "u-acme-admin", "acme", "system")
	s.AddToken(TokenFor("u-acme-manager", "acme"), "u-acme-manager", "acme", "system")
	s.AddToken(TokenFor("u-acme-v", "acme"), "u-acme-v", "acme", "system")
	s.AddToken(TokenFor("u-acme-v2", "acme"), "u-acme-v2", "acme", "system")
	s.AddToken(TokenFor("u-multi", "acme"), "u-multi", "acme", "system")
	s.AddToken(TokenFor("u-multi", "globex"), "u-multi", "globex", "system")
	s.AddToken(TokenFor("u-globex-admin", "globex"), "u-globex-admin", "globex", "system")

	// --- baseline records --------------------------------------------------
	acmeAdmin := principal{UserID: "u-acme-admin", Role: RoleAdmin}
	if err := seedAcmeBaseline(s, acmeAdmin); err != nil {
		return err
	}
	globexAdmin := principal{UserID: "u-globex-admin", Role: RoleAdmin}
	if err := seedGlobexBaseline(s, globexAdmin); err != nil {
		return err
	}
	// Record the seeding itself in the audit trail.
	recordSeedAudit(s)
	return nil
}

func seedAcmeBaseline(s *Store, admin principal) error {
	// products
	prod1, err := createFor(s, "products", "acme", admin, map[string]any{
		"sku": "SKU-1", "name": "Widget", "unitPrice": 10.0, "description": "A standard widget",
	})
	if err != nil {
		return err
	}
	prod2, err := createFor(s, "products", "acme", admin, map[string]any{
		"sku": "SKU-2", "name": "Gadget", "unitPrice": 20.0,
	})
	if err != nil {
		return err
	}
	// prices (parent: products)
	if _, err := createFor(s, "prices", "acme", admin, map[string]any{
		"product": prod1, "amount": 12.5, "currency": "USD",
	}); err != nil {
		return err
	}
	if _, err := createFor(s, "prices", "acme", admin, map[string]any{
		"product": prod2, "amount": 22.0, "currency": "USD",
	}); err != nil {
		return err
	}
	// inventory (parent: products)
	if _, err := createFor(s, "inventory", "acme", admin, map[string]any{
		"product": prod1, "quantity": 100, "warehouse": "wh-1",
	}); err != nil {
		return err
	}
	// customers
	cust, err := createFor(s, "customers", "acme", admin, map[string]any{
		"name": "Jane Buyer", "email": "jane@example.com",
	})
	if err != nil {
		return err
	}
	// orders owned by two different viewers, so "own vs other" is demonstrable
	ordOwn, err := createFor(s, "orders", "acme", admin, map[string]any{
		"customer": cust, "owner": "u-acme-v", "status": "paid", "total": 40.0,
	})
	if err != nil {
		return err
	}
	if _, err := createFor(s, "orders", "acme", admin, map[string]any{
		"customer": cust, "owner": "u-acme-v2", "status": "open", "total": 80.0,
	}); err != nil {
		return err
	}
	// payments / refunds / invoice for the viewer's own order
	if _, err := createFor(s, "payments", "acme", admin, map[string]any{
		"order": ordOwn, "amount": 40.0, "currency": "USD", "status": "settled",
	}); err != nil {
		return err
	}
	if _, err := createFor(s, "refunds", "acme", admin, map[string]any{
		"order": ordOwn, "amount": 5.0, "currency": "USD", "reason": "return", "status": "approved",
	}); err != nil {
		return err
	}
	if _, err := createFor(s, "invoices", "acme", admin, map[string]any{
		"order": ordOwn, "owner": "u-acme-v", "amount": 40.0, "currency": "USD", "status": "paid",
	}); err != nil {
		return err
	}
	// api-keys
	if _, err := createFor(s, "api-keys", "acme", admin, map[string]any{
		"name": "prod-key", "key": "sk-live-abc",
	}); err != nil {
		return err
	}
	return nil
}

func seedGlobexBaseline(s *Store, admin principal) error {
	if _, err := createFor(s, "products", "globex", admin, map[string]any{
		"sku": "GLX-1", "name": "Globex Thing", "unitPrice": 99.0,
	}); err != nil {
		return err
	}
	if _, err := createFor(s, "orders", "globex", admin, map[string]any{
		"customer": "globex-cust", "owner": "u-multi", "status": "open", "total": 99.0,
	}); err != nil {
		return err
	}
	return nil
}

func recordSeedAudit(s *Store) {
	// audit logs are not directly writable; append a marker entry per tenant.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range []string{"acme", "globex"} {
		s.audit[t] = append(s.audit[t], &AuditEntry{
			ID:        s.nextID("audit"),
			Tenant:    t,
			Actor:     "system",
			Action:    "seed",
			Resource:  "system",
			Result:    "ok",
			Timestamp: now(),
		})
	}
}

// createFor is a seeding helper that returns the new record's id.
func createFor(s *Store, resource, tenant string, actor principal, fields map[string]any) (string, error) {
	rec, status := s.CreateRecord(resource, tenant, actor, fields)
	if status != 0 {
		return "", newErr(status, "seed_error", "seeding failed for "+resource)
	}
	r, ok := rec.(*Record)
	if !ok {
		return "", newErr(statusOK, "seed_error", "unexpected record type")
	}
	return r.ID, nil
}

// LogFixtures prints the public opaque-token fixtures so an operator/evaluator
// can authenticate. Each entry prints the EXACT token string that SeedAll
// registered for that (user, tenant) pair.
func LogFixtures(s *Store) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log.Print("seeded tokens (Authorization: Bearer <token>):")
	// (user, tenant, note) — token string is derived as TokenFor(user, tenant).
	pairs := []struct{ user, tenant, note string }{
		{"u-acme-admin", "acme", "admin"},
		{"u-acme-manager", "acme", "manager"},
		{"u-acme-v", "acme", "viewer"},
		{"u-acme-v2", "acme", "viewer (owner of another order/invoice)"},
		{"u-multi", "acme", "admin (tenant-specific role)"},
		{"u-multi", "globex", "viewer (tenant-specific role)"},
		{"u-globex-admin", "globex", "admin"},
	}
	for _, p := range pairs {
		t := TokenFor(p.user, p.tenant)
		// Confirm the token is actually registered (defensive, avoids logging a
		// string that does not authenticate).
		if _, ok := s.tokens[t]; !ok {
			log.Printf("  (warning: %s not registered, skipping)", t)
			continue
		}
		log.Printf("  %-12s / %-14s %-38s Bearer %s", p.tenant, p.user, p.note, t)
	}
}
