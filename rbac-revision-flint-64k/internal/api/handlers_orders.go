package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

type createOrderInput struct {
	CustomerID string            `json:"customerId"`
	Status     string            `json:"status"`
	Items      []model.OrderItem `json:"items"`
}

func (s *Server) handleOrdersList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "orders", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	customerID := q.Get("customerId")
	status := q.Get("status")
	if identity.Role == "viewer" {
		customerID = identity.UserID
	}
	limit, offset := parsePagination(r)
	orders, total, err := s.store.ListOrders(identity.TenantID, customerID, status, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list orders")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Order]{Data: orders, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleOrderCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "orders", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input createOrderInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.CustomerID == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "customerId is required")
		return
	}
	if len(input.Items) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "items are required")
		return
	}
	var total float64
	for _, it := range input.Items {
		if it.ProductID == "" || it.Quantity <= 0 || it.UnitPrice <= 0 {
			writeError(w, http.StatusBadRequest, "validation_failed", "items require productId, quantity and unitPrice")
			return
		}
		total += float64(it.Quantity) * it.UnitPrice
	}
	status := input.Status
	if status == "" {
		status = "pending"
	}
	created, err := s.store.CreateOrder(identity.TenantID, input.CustomerID, status, input.Items, total, identity.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create order")
		return
	}
	s.writeAudit(identity, "order.created", "orders", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleOrderGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "orders", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	order, ok := s.store.GetOrder(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	if order.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if identity.Role == "viewer" && order.CustomerID != identity.UserID {
		writeError(w, http.StatusForbidden, "forbidden", "order not accessible for this user")
		return
	}
	writeJSON(w, http.StatusOK, order)
}

func (s *Server) handleOrderUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "orders", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	order, ok := s.store.GetOrder(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	if order.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input createOrderInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.CustomerID == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "customerId is required")
		return
	}
	if len(input.Items) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "items are required")
		return
	}
	var total float64
	for _, it := range input.Items {
		if it.ProductID == "" || it.Quantity <= 0 || it.UnitPrice <= 0 {
			writeError(w, http.StatusBadRequest, "validation_failed", "items require productId, quantity and unitPrice")
			return
		}
		total += float64(it.Quantity) * it.UnitPrice
	}
	order.CustomerID = input.CustomerID
	order.Items = input.Items
	order.Total = total
	if input.Status != "" {
		order.Status = input.Status
	}
	order.UpdatedAt = time.Now()
	s.store.UpdateOrder(order)
	s.writeAudit(identity, "order.updated", "orders", order.ID)
	writeJSON(w, http.StatusOK, order)
}

func (s *Server) handleOrderDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "orders", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	order, ok := s.store.GetOrder(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	if order.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteOrder(id) {
		writeError(w, http.StatusNotFound, "not_found", "order not found")
		return
	}
	s.writeAudit(identity, "order.deleted", "orders", id)
	writeJSON(w, http.StatusNoContent, nil)
}
