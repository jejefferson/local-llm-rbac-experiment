package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleInvoicesList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "invoices", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	customerID := q.Get("customerId")
	orderID := q.Get("orderId")
	if identity.Role == "viewer" {
		customerID = identity.UserID
	}
	limit, offset := parsePagination(r)
	invoices, total, err := s.store.ListInvoices(identity.TenantID, customerID, orderID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list invoices")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Invoice]{Data: invoices, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleInvoiceCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "invoices", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		OrderID string `json:"orderId"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.OrderID == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "orderId is required")
		return
	}
	order, ok := s.store.GetOrder(input.OrderID)
	if !ok || order.TenantID != identity.TenantID {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	created, err := s.store.CreateInvoice(identity.TenantID, input.OrderID, order.CustomerID, order.Total, "issued")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create invoice")
		return
	}
	s.writeAudit(identity, "invoice.created", "invoices", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleInvoiceGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "invoices", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	invoice, ok := s.store.GetInvoice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "invoice not found")
		return
	}
	if invoice.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if identity.Role == "viewer" && invoice.CustomerID != identity.UserID {
		writeError(w, http.StatusForbidden, "forbidden", "invoice not accessible for this user")
		return
	}
	writeJSON(w, http.StatusOK, invoice)
}

func (s *Server) handleInvoiceUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "invoices", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	invoice, ok := s.store.GetInvoice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "invoice not found")
		return
	}
	if invoice.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.Status == "" {
		input.Status = invoice.Status
	}
	invoice.Status = input.Status
	invoice.UpdatedAt = time.Now()
	s.store.UpdateInvoice(invoice)
	s.writeAudit(identity, "invoice.updated", "invoices", invoice.ID)
	writeJSON(w, http.StatusOK, invoice)
}

func (s *Server) handleInvoiceDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "invoices", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	invoice, ok := s.store.GetInvoice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "invoice not found")
		return
	}
	if invoice.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteInvoice(id) {
		writeError(w, http.StatusNotFound, "not_found", "invoice not found")
		return
	}
	s.writeAudit(identity, "invoice.deleted", "invoices", id)
	writeJSON(w, http.StatusNoContent, nil)
}
