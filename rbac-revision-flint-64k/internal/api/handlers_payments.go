package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handlePaymentsList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "payments", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	invoiceID := q.Get("invoiceId")
	limit, offset := parsePagination(r)
	payments, total, err := s.store.ListPayments(identity.TenantID, invoiceID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list payments")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Payment]{Data: payments, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handlePaymentCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "payments", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		InvoiceID string  `json:"invoiceId"`
		Amount    float64 `json:"amount"`
		Method    string  `json:"method"`
		Status    string  `json:"status"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.InvoiceID == "" || input.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "invoiceId and amount are required")
		return
	}
	invoice, ok := s.store.GetInvoice(input.InvoiceID)
	if !ok || invoice.TenantID != identity.TenantID {
		writeError(w, http.StatusNotFound, "not_found", "invoice not found")
		return
	}
	status := input.Status
	if status == "" {
		status = "pending"
	}
	created, err := s.store.CreatePayment(identity.TenantID, input.InvoiceID, input.Amount, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create payment")
		return
	}
	s.writeAudit(identity, "payment.created", "payments", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handlePaymentGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "payments", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	payment, ok := s.store.GetPayment(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "payment not found")
		return
	}
	if payment.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, payment)
}

func (s *Server) handlePaymentUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "payments", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	payment, ok := s.store.GetPayment(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "payment not found")
		return
	}
	if payment.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		Amount float64 `json:"amount"`
		Status string  `json:"status"`
		Method string  `json:"method"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	payment.Amount = input.Amount
	payment.Status = input.Status
	payment.Method = input.Method
	payment.UpdatedAt = time.Now()
	s.store.UpdatePayment(payment)
	s.writeAudit(identity, "payment.updated", "payments", payment.ID)
	writeJSON(w, http.StatusOK, payment)
}

func (s *Server) handlePaymentDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "payments", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	payment, ok := s.store.GetPayment(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "payment not found")
		return
	}
	if payment.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeletePayment(id) {
		writeError(w, http.StatusNotFound, "not_found", "payment not found")
		return
	}
	s.writeAudit(identity, "payment.deleted", "payments", id)
	writeJSON(w, http.StatusNoContent, nil)
}
