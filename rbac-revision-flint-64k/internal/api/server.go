package api

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"rbac/internal/auth"
	"rbac/internal/store"
)

type identityContextKey struct{}

// Server wires the RBAC store, auth resolver and HTTP handlers.
type Server struct {
	store *store.Store
	auth  *auth.Auth
}

func NewServer(s *store.Store) *Server {
	return &Server{store: s, auth: auth.New(s)}
}

// Handler returns the HTTP handler implementing the public API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/products", s.withAuth(s.handleProductsList))
	mux.HandleFunc("POST /v1/products", s.withAuth(s.handleProductCreate))
	mux.HandleFunc("GET /v1/products/{id}", s.withAuth(s.handleProductGet))
	mux.HandleFunc("PUT /v1/products/{id}", s.withAuth(s.handleProductUpdate))
	mux.HandleFunc("DELETE /v1/products/{id}", s.withAuth(s.handleProductDelete))

	mux.HandleFunc("GET /v1/prices", s.withAuth(s.handlePricesList))
	mux.HandleFunc("POST /v1/prices", s.withAuth(s.handlePriceCreate))
	mux.HandleFunc("GET /v1/prices/{id}", s.withAuth(s.handlePriceGet))
	mux.HandleFunc("PUT /v1/prices/{id}", s.withAuth(s.handlePriceUpdate))
	mux.HandleFunc("DELETE /v1/prices/{id}", s.withAuth(s.handlePriceDelete))

	mux.HandleFunc("GET /v1/orders", s.withAuth(s.handleOrdersList))
	mux.HandleFunc("POST /v1/orders", s.withAuth(s.handleOrderCreate))
	mux.HandleFunc("GET /v1/orders/{id}", s.withAuth(s.handleOrderGet))
	mux.HandleFunc("PUT /v1/orders/{id}", s.withAuth(s.handleOrderUpdate))
	mux.HandleFunc("DELETE /v1/orders/{id}", s.withAuth(s.handleOrderDelete))

	mux.HandleFunc("GET /v1/customers", s.withAuth(s.handleCustomersList))
	mux.HandleFunc("POST /v1/customers", s.withAuth(s.handleCustomerCreate))
	mux.HandleFunc("GET /v1/customers/{id}", s.withAuth(s.handleCustomerGet))
	mux.HandleFunc("PUT /v1/customers/{id}", s.withAuth(s.handleCustomerUpdate))
	mux.HandleFunc("DELETE /v1/customers/{id}", s.withAuth(s.handleCustomerDelete))

	mux.HandleFunc("GET /v1/invoices", s.withAuth(s.handleInvoicesList))
	mux.HandleFunc("POST /v1/invoices", s.withAuth(s.handleInvoiceCreate))
	mux.HandleFunc("GET /v1/invoices/{id}", s.withAuth(s.handleInvoiceGet))
	mux.HandleFunc("PUT /v1/invoices/{id}", s.withAuth(s.handleInvoiceUpdate))
	mux.HandleFunc("DELETE /v1/invoices/{id}", s.withAuth(s.handleInvoiceDelete))

	mux.HandleFunc("GET /v1/payments", s.withAuth(s.handlePaymentsList))
	mux.HandleFunc("POST /v1/payments", s.withAuth(s.handlePaymentCreate))
	mux.HandleFunc("GET /v1/payments/{id}", s.withAuth(s.handlePaymentGet))
	mux.HandleFunc("PUT /v1/payments/{id}", s.withAuth(s.handlePaymentUpdate))
	mux.HandleFunc("DELETE /v1/payments/{id}", s.withAuth(s.handlePaymentDelete))

	mux.HandleFunc("GET /v1/refunds", s.withAuth(s.handleRefundsList))
	mux.HandleFunc("POST /v1/refunds", s.withAuth(s.handleRefundCreate))
	mux.HandleFunc("GET /v1/refunds/{id}", s.withAuth(s.handleRefundGet))
	mux.HandleFunc("PUT /v1/refunds/{id}", s.withAuth(s.handleRefundUpdate))
	mux.HandleFunc("DELETE /v1/refunds/{id}", s.withAuth(s.handleRefundDelete))

	mux.HandleFunc("GET /v1/inventory", s.withAuth(s.handleInventoryList))
	mux.HandleFunc("POST /v1/inventory", s.withAuth(s.handleInventoryCreate))
	mux.HandleFunc("GET /v1/inventory/{id}", s.withAuth(s.handleInventoryGet))
	mux.HandleFunc("PUT /v1/inventory/{id}", s.withAuth(s.handleInventoryUpdate))
	mux.HandleFunc("DELETE /v1/inventory/{id}", s.withAuth(s.handleInventoryDelete))

	mux.HandleFunc("GET /v1/api-keys", s.withAuth(s.handleApiKeysList))
	mux.HandleFunc("POST /v1/api-keys", s.withAuth(s.handleApiKeyCreate))
	mux.HandleFunc("GET /v1/api-keys/{id}", s.withAuth(s.handleApiKeyGet))
	mux.HandleFunc("PUT /v1/api-keys/{id}", s.withAuth(s.handleApiKeyUpdate))
	mux.HandleFunc("DELETE /v1/api-keys/{id}", s.withAuth(s.handleApiKeyDelete))

	mux.HandleFunc("GET /v1/audit-logs", s.withAuth(s.handleAuditLogsList))

	mux.HandleFunc("GET /v1/members", s.withAuth(s.handleMembersList))
	mux.HandleFunc("PUT /v1/members/{userId}", s.withAuth(s.handleMemberUpdate))
	mux.HandleFunc("DELETE /v1/members/{userId}", s.withAuth(s.handleMemberDelete))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		method, allowed := allowedMethodForPath(r.URL.Path, r.Method)
		if allowed {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	})

	return mux
}

// allowedMethodForPath reports whether the given path is a known API path on
// which the given HTTP method is not allowed. The second return value reports
// whether a 405 response is appropriate.
func allowedMethodForPath(path string, method string) (string, bool) {
	allowedByPath := map[string]map[string]bool{
		"/v1/products":   {http.MethodGet: true, http.MethodPost: true},
		"/v1/prices":     {http.MethodGet: true, http.MethodPost: true},
		"/v1/orders":     {http.MethodGet: true, http.MethodPost: true},
		"/v1/customers":  {http.MethodGet: true, http.MethodPost: true},
		"/v1/invoices":   {http.MethodGet: true, http.MethodPost: true},
		"/v1/payments":   {http.MethodGet: true, http.MethodPost: true},
		"/v1/refunds":    {http.MethodGet: true, http.MethodPost: true},
		"/v1/inventory":  {http.MethodGet: true, http.MethodPost: true},
		"/v1/api-keys":   {http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodDelete: true},
		"/v1/audit-logs": {http.MethodGet: true},
		"/v1/members":    {http.MethodGet: true, http.MethodPut: true, http.MethodDelete: true},
	}
	if allowed, ok := allowedByPath[path]; ok {
		if allowed[method] {
			return "", false
		}
		allow := make([]string, 0, len(allowed))
		for m := range allowed {
			allow = append(allow, m)
		}
		sort.Strings(allow)
		return strings.Join(allow, ", "), true
	}
	if idx := strings.Index(path, "/v1/"); idx >= 0 {
		rest := strings.TrimPrefix(path, "/v1/")
		parts := strings.Split(rest, "/")
		if len(parts) == 2 && parts[1] != "" {
			switch parts[0] {
			case "products", "prices", "orders", "customers", "invoices", "payments", "refunds", "inventory", "api-keys":
				allowed := map[string]bool{
					http.MethodGet:    true,
					http.MethodPut:    true,
					http.MethodDelete: true,
				}
				if allowed[method] {
					return "", false
				}
				allow := make([]string, 0, len(allowed))
				for m := range allowed {
					allow = append(allow, m)
				}
				sort.Strings(allow)
				return strings.Join(allow, ", "), true
			case "members":
				allowed := map[string]bool{
					http.MethodPut:    true,
					http.MethodDelete: true,
				}
				if allowed[method] {
					return "", false
				}
				allow := make([]string, 0, len(allowed))
				for m := range allowed {
					allow = append(allow, m)
				}
				sort.Strings(allow)
				return strings.Join(allow, ", "), true
			}
		}
	}
	return "", false
}

// withAuth wraps an authenticated handler, resolving the caller identity.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.auth.Authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
		next(w, r.WithContext(ctx))
	}
}

// currentIdentity returns the identity resolved for the request context.
func (s *Server) currentIdentity(r *http.Request) *auth.Identity {
	identity, ok := r.Context().Value(identityContextKey{}).(*auth.Identity)
	if !ok || identity == nil {
		return &auth.Identity{}
	}
	return identity
}

// ListenAndServe starts the HTTP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}
