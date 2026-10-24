package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"rbac/internal/model"
)

// repo is a generic in-memory collection keyed by entity key function.
type repo[T any] struct {
	mu    sync.RWMutex
	items map[string]*T
	key   func(*T) string
}

func newRepo[T any](key func(*T) string) *repo[T] {
	return &repo[T]{items: make(map[string]*T), key: key}
}

func (r *repo[T]) Get(id string) (*T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	it, ok := r.items[id]
	return it, ok
}

func (r *repo[T]) Put(item *T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[r.key(item)] = item
}

func (r *repo[T]) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.items[id]
	delete(r.items, id)
	return ok
}

func (r *repo[T]) All() []*T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*T, len(keys))
	for i, k := range keys {
		out[i] = r.items[k]
	}
	return out
}

// Store is the thread-safe in-memory database for the RBAC service.
type Store struct {
	mu        sync.RWMutex
	tenants   map[string]*model.Tenant
	members   map[string]map[string]string // tenant -> user -> role
	products  *repo[model.Product]
	prices    *repo[model.Price]
	orders    *repo[model.Order]
	customers *repo[model.Customer]
	invoices  *repo[model.Invoice]
	payments  *repo[model.Payment]
	refunds   *repo[model.Refund]
	inventory *repo[model.InventoryItem]
	apiKeys   *repo[model.ApiKey]
	auditLogs *repo[model.AuditLog]
	tokens    map[string]string // token -> "tenant:user"
	seq       map[string]int
	seqMu     sync.Mutex
}

func New() *Store {
	s := &Store{
		tenants:   map[string]*model.Tenant{},
		members:   map[string]map[string]string{},
		products:  newRepo[model.Product](func(t *model.Product) string { return t.ID }),
		prices:    newRepo[model.Price](func(t *model.Price) string { return t.ID }),
		orders:    newRepo[model.Order](func(t *model.Order) string { return t.ID }),
		customers: newRepo[model.Customer](func(t *model.Customer) string { return t.ID }),
		invoices:  newRepo[model.Invoice](func(t *model.Invoice) string { return t.ID }),
		payments:  newRepo[model.Payment](func(t *model.Payment) string { return t.ID }),
		refunds:   newRepo[model.Refund](func(t *model.Refund) string { return t.ID }),
		inventory: newRepo[model.InventoryItem](func(t *model.InventoryItem) string { return t.ID }),
		apiKeys:   newRepo[model.ApiKey](func(t *model.ApiKey) string { return t.ID }),
		auditLogs: newRepo[model.AuditLog](func(t *model.AuditLog) string { return t.ID }),
		tokens:    map[string]string{},
		seq:       map[string]int{},
	}
	s.seed()
	s.nextIDsAfterSeeds()
	return s
}

func (s *Store) seed() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tenants["acme"] = &model.Tenant{ID: "acme", Name: "Acme Corporation"}
	s.tenants["globex"] = &model.Tenant{ID: "globex", Name: "Globex Inc"}

	memberships := map[string]map[string]string{
		"acme":   {"admin": "admin", "emma": "manager", "liam": "viewer"},
		"globex": {"admin": "admin", "olaf": "manager", "nina": "viewer"},
	}
	for tenant, members := range memberships {
		s.members[tenant] = members
		for userID := range members {
			tok := tenant + ":" + userID
			s.tokens[tok] = tok
		}
	}

	now := time.Now()
	created := now.AddDate(0, 0, -2)
	hoursAgo := func(h float64) time.Time { return now.Add(-time.Duration(h) * time.Hour) }

	s.products.Put(&model.Product{Base: model.Base{ID: "prd_acme_1", TenantID: "acme", CreatedAt: created, UpdatedAt: created}, SKU: "WM-100", Name: "Wireless Mouse", Description: "Ergonomic 2.4GHz wireless mouse", Price: 25.99, Currency: "USD"})
	s.products.Put(&model.Product{Base: model.Base{ID: "prd_acme_2", TenantID: "acme", CreatedAt: created, UpdatedAt: created}, SKU: "KB-200", Name: "Mechanical Keyboard", Description: "Hot-swappable mechanical keyboard", Price: 89.99, Currency: "USD"})
	s.products.Put(&model.Product{Base: model.Base{ID: "prd_globex_1", TenantID: "globex", CreatedAt: created, UpdatedAt: created}, SKU: "WM-101", Name: "Wireless Mouse", Description: "Ergonomic 2.4GHz wireless mouse", Price: 27.5, Currency: "USD"})
	s.products.Put(&model.Product{Base: model.Base{ID: "prd_globex_2", TenantID: "globex", CreatedAt: created, UpdatedAt: created}, SKU: "KB-201", Name: "Mechanical Keyboard", Description: "Hot-swappable mechanical keyboard", Price: 95, Currency: "USD"})

	s.prices.Put(&model.Price{Base: model.Base{ID: "prc_acme_1", TenantID: "acme", CreatedAt: created}, ProductID: "prd_acme_1", Amount: 25.99, Currency: "USD"})
	s.prices.Put(&model.Price{Base: model.Base{ID: "prc_acme_2", TenantID: "acme", CreatedAt: created}, ProductID: "prd_acme_2", Amount: 89.99, Currency: "USD"})
	s.prices.Put(&model.Price{Base: model.Base{ID: "prc_globex_1", TenantID: "globex", CreatedAt: created}, ProductID: "prd_globex_1", Amount: 27.5, Currency: "USD"})
	s.prices.Put(&model.Price{Base: model.Base{ID: "prc_globex_2", TenantID: "globex", CreatedAt: created}, ProductID: "prd_globex_2", Amount: 95, Currency: "USD"})

	s.customers.Put(&model.Customer{Base: model.Base{ID: "cus_acme_1", TenantID: "acme", CreatedAt: created}, Name: "Acme Corporation", Email: "finance@acme.example"})
	s.customers.Put(&model.Customer{Base: model.Base{ID: "cus_globex_1", TenantID: "globex", CreatedAt: created}, Name: "Globex Inc", Email: "ap@globex.example"})

	s.orders.Put(&model.Order{Base: model.Base{ID: "ord_acme_1", TenantID: "acme", CreatedAt: created, UpdatedAt: created}, CustomerID: "liam", Status: "delivered", Items: []model.OrderItem{{ProductID: "prd_acme_1", Quantity: 1, UnitPrice: 25.99}, {ProductID: "prd_acme_2", Quantity: 2, UnitPrice: 89.99}}, Total: 205.97, CreatedBy: "admin"})
	s.orders.Put(&model.Order{Base: model.Base{ID: "ord_acme_2", TenantID: "acme", CreatedAt: hoursAgo(3), UpdatedAt: hoursAgo(3)}, CustomerID: "emma", Status: "pending", Items: []model.OrderItem{{ProductID: "prd_acme_1", Quantity: 2, UnitPrice: 25.99}}, Total: 51.98, CreatedBy: "admin"})
	s.orders.Put(&model.Order{Base: model.Base{ID: "ord_globex_1", TenantID: "globex", CreatedAt: created, UpdatedAt: created}, CustomerID: "nina", Status: "delivered", Items: []model.OrderItem{{ProductID: "prd_globex_1", Quantity: 1, UnitPrice: 27.5}, {ProductID: "prd_globex_2", Quantity: 1, UnitPrice: 95}}, Total: 122.5, CreatedBy: "admin"})
	s.orders.Put(&model.Order{Base: model.Base{ID: "ord_globex_2", TenantID: "globex", CreatedAt: hoursAgo(5), UpdatedAt: hoursAgo(5)}, CustomerID: "olaf", Status: "pending", Items: []model.OrderItem{{ProductID: "prd_globex_1", Quantity: 3, UnitPrice: 27.5}}, Total: 82.5, CreatedBy: "admin"})

	s.invoices.Put(&model.Invoice{Base: model.Base{ID: "invc_acme_1", TenantID: "acme", CreatedAt: created}, OrderID: "ord_acme_1", CustomerID: "liam", Status: "paid", Amount: 205.97})
	s.invoices.Put(&model.Invoice{Base: model.Base{ID: "invc_acme_2", TenantID: "acme", CreatedAt: hoursAgo(3)}, OrderID: "ord_acme_2", CustomerID: "emma", Status: "issued", Amount: 51.98})
	s.invoices.Put(&model.Invoice{Base: model.Base{ID: "invc_globex_1", TenantID: "globex", CreatedAt: created}, OrderID: "ord_globex_1", CustomerID: "nina", Status: "paid", Amount: 122.5})
	s.invoices.Put(&model.Invoice{Base: model.Base{ID: "invc_globex_2", TenantID: "globex", CreatedAt: hoursAgo(5)}, OrderID: "ord_globex_2", CustomerID: "olaf", Status: "issued", Amount: 82.5})

	s.payments.Put(&model.Payment{Base: model.Base{ID: "pay_acme_1", TenantID: "acme", CreatedAt: created}, InvoiceID: "invc_acme_1", OrderID: "ord_acme_1", Amount: 205.97, Status: "captured", Method: "card"})
	s.payments.Put(&model.Payment{Base: model.Base{ID: "pay_globex_1", TenantID: "globex", CreatedAt: created}, InvoiceID: "invc_globex_1", OrderID: "ord_globex_1", Amount: 122.5, Status: "captured", Method: "card"})

	s.refunds.Put(&model.Refund{Base: model.Base{ID: "ref_acme_1", TenantID: "acme", CreatedAt: hoursAgo(20)}, PaymentID: "pay_acme_1", OrderID: "ord_acme_1", Amount: 25.99, Status: "pending", Reason: "Defective sensor"})

	s.inventory.Put(&model.InventoryItem{Base: model.Base{ID: "inv_acme_1", TenantID: "acme", CreatedAt: created}, ProductID: "prd_acme_1", Quantity: 42, Reserved: 2})
	s.inventory.Put(&model.InventoryItem{Base: model.Base{ID: "inv_globex_1", TenantID: "globex", CreatedAt: created}, ProductID: "prd_globex_1", Quantity: 7, Reserved: 1})

	s.apiKeys.Put(&model.ApiKey{Base: model.Base{ID: "key_acme_1", TenantID: "acme", CreatedAt: created}, Name: "Production API Key", KeyID: "keyid_acme_1", Secret: "sk_live_acme_1", Status: "active"})
	s.apiKeys.Put(&model.ApiKey{Base: model.Base{ID: "key_globex_1", TenantID: "globex", CreatedAt: created}, Name: "Production API Key", KeyID: "keyid_globex_1", Secret: "sk_live_globex_1", Status: "active"})

	s.auditLogs.Put(&model.AuditLog{Base: model.Base{ID: "aud_acme_1", TenantID: "acme", CreatedAt: created}, Action: "order.created", Actor: "admin", Resource: "orders", Details: "ord_acme_1"})
}

// nextIDsAfterSeeds advances the ID sequence past the seeded entities.
func (s *Store) nextIDsAfterSeeds() {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	lasts := map[string]int{
		"prd": 2, "prc": 2, "ord": 2, "invc": 2, "pay": 2, "ref": 2, "inv": 2, "key": 2, "aud": 2,
	}
	for prefix, last := range lasts {
		s.seq[prefix] = last
	}
}

func (s *Store) GetTenant(id string) (*model.Tenant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	return t, ok
}

// ---------- members & tokens ----------

func (s *Store) ListMembers(tenant string) []model.Membership {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []model.Membership{}
	for userID, role := range s.members[tenant] {
		out = append(out, model.Membership{TenantID: tenant, UserID: userID, Role: role})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out
}

func (s *Store) GetMemberRole(tenantID, userID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	role, ok := s.members[tenantID][userID]
	return role, ok
}

func (s *Store) HasMember(tenantID, userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.members[tenantID][userID]
	return ok
}

func (s *Store) UpdateMemberRole(tenantID, userID, role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[tenantID]; !ok {
		return false
	}
	if _, ok := s.members[tenantID][userID]; !ok {
		return false
	}
	s.members[tenantID][userID] = role
	return true
}

func (s *Store) DeleteMember(tenantID, userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	members, ok := s.members[tenantID]
	if !ok {
		return false
	}
	if _, ok := members[userID]; !ok {
		return false
	}
	delete(members, userID)
	return true
}

// LookupToken resolves an opaque bearer token to a tenant user.
func (s *Store) LookupToken(token string) (string, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[token]
	if !ok {
		return "", "", false
	}
	tenantID, userID, ok := strings.Cut(t, ":")
	if !ok || userID == "" {
		return "", "", false
	}
	if _, ok := s.members[tenantID][userID]; !ok {
		return "", "", false
	}
	return tenantID, userID, true
}

// NextID mints an entity ID of the form <prefix>_<tenant>_<seq>.
func (s *Store) NextID(prefix string, tenantID string) string {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	n := s.seq[prefix] + 1
	s.seq[prefix] = n
	return fmt.Sprintf("%s_%s_%d", prefix, tenantID, n)
}

// ---------- products ----------

func (s *Store) ListProducts(tenantID, q string, limit, offset int) ([]*model.Product, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Product{}
	for _, p := range s.products.All() {
		if p.TenantID != tenantID {
			continue
		}
		if q != "" {
			needle := strings.ToLower(q)
			if !strings.Contains(strings.ToLower(p.Name), needle) && !strings.Contains(strings.ToLower(p.SKU), needle) {
				continue
			}
		}
		out = append(out, p)
	}
	return paginate(out, limit, offset)
}

func (s *Store) GetProduct(id string) (*model.Product, bool) {
	return s.products.Get(id)
}

func (s *Store) CreateProduct(tenantID, sku, name string, price float64, currency string, description string) (*model.Product, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	p := &model.Product{Base: model.Base{ID: s.NextID("prd", tenantID), TenantID: tenantID, CreatedAt: now, UpdatedAt: now}, SKU: sku, Name: name, Description: description, Price: price, Currency: currency}
	s.products.Put(p)
	return p, nil
}

func (s *Store) UpdateProduct(p *model.Product) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.products.Put(p)
}

func (s *Store) DeleteProduct(id string) bool {
	return s.products.Delete(id)
}

// ---------- prices ----------

func (s *Store) ListPrices(tenantID, productID string, limit, offset int) ([]*model.Price, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Price{}
	for _, pr := range s.prices.All() {
		if pr.TenantID != tenantID {
			continue
		}
		if productID != "" && pr.ProductID != productID {
			continue
		}
		out = append(out, pr)
	}
	return paginate(out, limit, offset)
}

func (s *Store) GetPrice(id string) (*model.Price, bool) { return s.prices.Get(id) }

func (s *Store) CreatePrice(tenantID, productID string, amount float64, currency string) (*model.Price, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	pr := &model.Price{Base: model.Base{ID: s.NextID("prc", tenantID), TenantID: tenantID, CreatedAt: now}, ProductID: productID, Amount: amount, Currency: currency}
	s.prices.Put(pr)
	return pr, nil
}

func (s *Store) UpdatePrice(pr *model.Price) { s.mu.Lock(); defer s.mu.Unlock(); s.prices.Put(pr) }

func (s *Store) DeletePrice(id string) bool { return s.prices.Delete(id) }

// ---------- orders ----------

func (s *Store) ListOrders(tenantID, customerID, status string, limit, offset int) ([]*model.Order, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Order{}
	for _, o := range s.orders.All() {
		if o.TenantID != tenantID {
			continue
		}
		if customerID != "" && o.CustomerID != customerID {
			continue
		}
		if status != "" && o.Status != status {
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return paginate(out, limit, offset)
}

func (s *Store) GetOrder(id string) (*model.Order, bool) { return s.orders.Get(id) }

func (s *Store) CreateOrder(tenantID, customerID, status string, items []model.OrderItem, total float64, createdBy string) (*model.Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	o := &model.Order{Base: model.Base{ID: s.NextID("ord", tenantID), TenantID: tenantID, CreatedAt: now, UpdatedAt: now}, CustomerID: customerID, Status: status, Items: items, Total: total, CreatedBy: createdBy}
	s.orders.Put(o)
	return o, nil
}

func (s *Store) UpdateOrder(o *model.Order) { s.mu.Lock(); defer s.mu.Unlock(); s.orders.Put(o) }

func (s *Store) DeleteOrder(id string) bool { return s.orders.Delete(id) }

// ---------- customers ----------

func (s *Store) ListCustomers(tenantID string, limit, offset int) ([]*model.Customer, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Customer{}
	for _, c := range s.customers.All() {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return paginate(out, limit, offset)
}

func (s *Store) GetCustomer(id string) (*model.Customer, bool) { return s.customers.Get(id) }

func (s *Store) CreateCustomer(tenantID string, name string, email string) (*model.Customer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	c := &model.Customer{Base: model.Base{ID: s.NextID("cus", tenantID), TenantID: tenantID, CreatedAt: now}, Name: name, Email: email}
	s.customers.Put(c)
	return c, nil
}

func (s *Store) UpdateCustomer(c *model.Customer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customers.Put(c)
}

func (s *Store) DeleteCustomer(id string) bool { return s.customers.Delete(id) }

// ---------- invoices ----------

func (s *Store) ListInvoices(tenantID, customerID, orderID string, limit, offset int) ([]*model.Invoice, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Invoice{}
	for _, inv := range s.invoices.All() {
		if inv.TenantID != tenantID {
			continue
		}
		if customerID != "" && inv.CustomerID != customerID {
			continue
		}
		if orderID != "" && inv.OrderID != orderID {
			continue
		}
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return paginate(out, limit, offset)
}

func (s *Store) GetInvoice(id string) (*model.Invoice, bool) { return s.invoices.Get(id) }

func (s *Store) CreateInvoice(tenantID, orderID, customerID string, amount float64, status string) (*model.Invoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	inv := &model.Invoice{Base: model.Base{ID: s.NextID("invc", tenantID), TenantID: tenantID, CreatedAt: now}, OrderID: orderID, CustomerID: customerID, Status: status, Amount: amount}
	s.invoices.Put(inv)
	return inv, nil
}

func (s *Store) UpdateInvoice(inv *model.Invoice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invoices.Put(inv)
}

func (s *Store) DeleteInvoice(id string) bool { return s.invoices.Delete(id) }

// ---------- payments ----------

func (s *Store) ListPayments(tenantID, invoiceID string, limit, offset int) ([]*model.Payment, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Payment{}
	for _, p := range s.payments.All() {
		if p.TenantID != tenantID {
			continue
		}
		if invoiceID != "" && p.InvoiceID != invoiceID {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return paginate(out, limit, offset)
}

func (s *Store) GetPayment(id string) (*model.Payment, bool) { return s.payments.Get(id) }

func (s *Store) CreatePayment(tenantID string, invoiceID string, amount float64, status string) (*model.Payment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	p := &model.Payment{Base: model.Base{ID: s.NextID("pay", tenantID), TenantID: tenantID, CreatedAt: now}, InvoiceID: invoiceID, Amount: amount, Status: status}
	s.payments.Put(p)
	return p, nil
}

func (s *Store) UpdatePayment(p *model.Payment) { s.mu.Lock(); defer s.mu.Unlock(); s.payments.Put(p) }

func (s *Store) DeletePayment(id string) bool { return s.payments.Delete(id) }

// ---------- refunds ----------

func (s *Store) ListRefunds(tenantID, paymentID string, limit, offset int) ([]*model.Refund, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.Refund{}
	for _, rf := range s.refunds.All() {
		if rf.TenantID != tenantID {
			continue
		}
		if paymentID != "" && rf.PaymentID != paymentID {
			continue
		}
		out = append(out, rf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return paginate(out, limit, offset)
}

func (s *Store) GetRefund(id string) (*model.Refund, bool) { return s.refunds.Get(id) }

func (s *Store) CreateRefund(tenantID, paymentID string, amount float64, reason string, status string) (*model.Refund, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	rf := &model.Refund{Base: model.Base{ID: s.NextID("ref", tenantID), TenantID: tenantID, CreatedAt: now}, PaymentID: paymentID, Amount: amount, Reason: reason, Status: status}
	s.refunds.Put(rf)
	return rf, nil
}

func (s *Store) UpdateRefund(rf *model.Refund) { s.mu.Lock(); defer s.mu.Unlock(); s.refunds.Put(rf) }

func (s *Store) DeleteRefund(id string) bool { return s.refunds.Delete(id) }

// ---------- inventory ----------

func (s *Store) ListInventory(tenantID, productID string, limit, offset int) ([]*model.InventoryItem, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.InventoryItem{}
	for _, it := range s.inventory.All() {
		if it.TenantID != tenantID {
			continue
		}
		if productID != "" && it.ProductID != productID {
			continue
		}
		out = append(out, it)
	}
	return paginate(out, limit, offset)
}

func (s *Store) GetInventory(id string) (*model.InventoryItem, bool) { return s.inventory.Get(id) }

func (s *Store) CreateInventory(tenantID, productID string, quantity int, reserved int) (*model.InventoryItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	it := &model.InventoryItem{Base: model.Base{ID: s.NextID("inv", tenantID), TenantID: tenantID, CreatedAt: now}, ProductID: productID, Quantity: quantity, Reserved: reserved}
	s.inventory.Put(it)
	return it, nil
}

func (s *Store) UpdateInventory(it *model.InventoryItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inventory.Put(it)
}

func (s *Store) DeleteInventory(id string) bool { return s.inventory.Delete(id) }

// ---------- api keys ----------

func (s *Store) ListApiKeys(tenantID string, limit, offset int) ([]*model.ApiKey, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.ApiKey{}
	for _, k := range s.apiKeys.All() {
		if k.TenantID == tenantID {
			out = append(out, k)
		}
	}
	return paginate(out, limit, offset)
}

func (s *Store) GetApiKey(id string) (*model.ApiKey, bool) { return s.apiKeys.Get(id) }

func (s *Store) CreateApiKey(tenantID, name string, keyID string, secret string, status string) (*model.ApiKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	k := &model.ApiKey{Base: model.Base{ID: s.NextID("key", tenantID), TenantID: tenantID, CreatedAt: now}, Name: name, KeyID: keyID, Secret: secret, Status: status}
	s.apiKeys.Put(k)
	return k, nil
}

func (s *Store) UpdateApiKey(k *model.ApiKey) { s.mu.Lock(); defer s.mu.Unlock(); s.apiKeys.Put(k) }

func (s *Store) DeleteApiKey(id string) bool { return s.apiKeys.Delete(id) }

// ---------- audit logs ----------

func (s *Store) ListAuditLogs(tenantID, actor, action, resource string, limit, offset int) ([]*model.AuditLog, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*model.AuditLog{}
	for _, a := range s.auditLogs.All() {
		if a.TenantID != tenantID {
			continue
		}
		if actor != "" && a.Actor != actor {
			continue
		}
		if action != "" && a.Action != action {
			continue
		}
		if resource != "" && a.Resource != resource {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return paginate(out, limit, offset)
}

func (s *Store) AppendAudit(a *model.AuditLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs.Put(a)
}

func (s *Store) GetAuditLog(id string) (*model.AuditLog, bool) { return s.auditLogs.Get(id) }

func paginate[T any](items []*T, limit, offset int) ([]*T, int, error) {
	if items == nil {
		items = []*T{}
	}
	total := len(items)
	start := offset
	if start < 0 {
		start = 0
	}
	end := start + limit
	if limit <= 0 || end > total {
		end = total
	}
	if start > end {
		start = end
	}
	return items[start:end], total, nil
}
