package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleRefundsList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "refunds", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	paymentID := q.Get("paymentId")
	limit, offset := parsePagination(r)
	refunds, total, err := s.store.ListRefunds(identity.TenantID, paymentID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list refunds")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Refund]{Data: refunds, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleRefundCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "refunds", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		PaymentID string  `json:"paymentId"`
		Amount    float64 `json:"amount"`
		Reason    string  `json:"reason"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.PaymentID == "" || input.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "paymentId and amount are required")
		return
	}
	payment, ok := s.store.GetPayment(input.PaymentID)
	if !ok || payment.TenantID != identity.TenantID {
		writeError(w, http.StatusNotFound, "not_found", "payment not found")
		return
	}
	created, err := s.store.CreateRefund(identity.TenantID, input.PaymentID, input.Amount, input.Reason, "pending")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create refund")
		return
	}
	s.writeAudit(identity, "refund.created", "refunds", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleRefundGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "refunds", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	refund, ok := s.store.GetRefund(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "refund not found")
		return
	}
	if refund.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, refund)
}

func (s *Server) handleRefundUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "refunds", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	refund, ok := s.store.GetRefund(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "refund not found")
		return
	}
	if refund.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		Amount float64 `json:"amount"`
		Reason string  `json:"reason"`
		Status string  `json:"status"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	refund.Amount = input.Amount
	refund.Reason = input.Reason
	refund.Status = input.Status
	refund.UpdatedAt = time.Now()
	s.store.UpdateRefund(refund)
	s.writeAudit(identity, "refund.updated", "refunds", refund.ID)
	writeJSON(w, http.StatusOK, refund)
}

func (s *Server) handleRefundDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "refunds", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	refund, ok := s.store.GetRefund(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "refund not found")
		return
	}
	if refund.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteRefund(id) {
		writeError(w, http.StatusNotFound, "not_found", "refund not found")
		return
	}
	s.writeAudit(identity, "refund.deleted", "refunds", id)
	writeJSON(w, http.StatusNoContent, nil)
}
