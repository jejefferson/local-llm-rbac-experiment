package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleInventoryList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "inventory", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	productID := q.Get("productId")
	limit, offset := parsePagination(r)
	items, total, err := s.store.ListInventory(identity.TenantID, productID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list inventory")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.InventoryItem]{Data: items, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleInventoryCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "inventory", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		ProductID string `json:"productId"`
		Quantity  int    `json:"quantity"`
		Reserved  int    `json:"reserved"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.ProductID == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "productId is required")
		return
	}
	created, err := s.store.CreateInventory(identity.TenantID, input.ProductID, input.Quantity, input.Reserved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create inventory item")
		return
	}
	s.writeAudit(identity, "inventory.created", "inventory", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleInventoryGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "inventory", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	item, ok := s.store.GetInventory(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "inventory item not found")
		return
	}
	if item.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleInventoryUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "inventory", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	item, ok := s.store.GetInventory(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "inventory item not found")
		return
	}
	if item.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		ProductID string `json:"productId"`
		Quantity  int    `json:"quantity"`
		Reserved  int    `json:"reserved"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	item.ProductID = input.ProductID
	item.Quantity = input.Quantity
	item.Reserved = input.Reserved
	item.UpdatedAt = time.Now()
	s.store.UpdateInventory(item)
	s.writeAudit(identity, "inventory.updated", "inventory", item.ID)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleInventoryDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "inventory", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	item, ok := s.store.GetInventory(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "inventory item not found")
		return
	}
	if item.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteInventory(id) {
		writeError(w, http.StatusNotFound, "not_found", "inventory item not found")
		return
	}
	s.writeAudit(identity, "inventory.deleted", "inventory", id)
	writeJSON(w, http.StatusNoContent, nil)
}
