package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleCustomersList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "customers", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	customers, total, err := s.store.ListCustomers(identity.TenantID, 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list customers")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Customer]{Data: customers, Total: total, Limit: 100, Offset: 0})
}

func (s *Server) handleCustomerCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "customers", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.Name == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "name is required")
		return
	}
	created, err := s.store.CreateCustomer(identity.TenantID, input.Name, input.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create customer")
		return
	}
	s.writeAudit(identity, "customer.created", "customers", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleCustomerGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "customers", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	customer, ok := s.store.GetCustomer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "customer not found")
		return
	}
	if customer.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, customer)
}

func (s *Server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "customers", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	customer, ok := s.store.GetCustomer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "customer not found")
		return
	}
	if customer.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	customer.Name = input.Name
	customer.Email = input.Email
	customer.UpdatedAt = time.Now()
	s.store.UpdateCustomer(customer)
	s.writeAudit(identity, "customer.updated", "customers", customer.ID)
	writeJSON(w, http.StatusOK, customer)
}

func (s *Server) handleCustomerDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "customers", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	customer, ok := s.store.GetCustomer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "customer not found")
		return
	}
	if customer.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteCustomer(id) {
		writeError(w, http.StatusNotFound, "not_found", "customer not found")
		return
	}
	s.writeAudit(identity, "customer.deleted", "customers", id)
	writeJSON(w, http.StatusNoContent, nil)
}
