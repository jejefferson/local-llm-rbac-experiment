package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handlePricesList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "prices", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	productID := r.URL.Query().Get("productId")
	prices, total, err := s.store.ListPrices(identity.TenantID, productID, 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list prices")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Price]{Data: prices, Total: total, Limit: 100, Offset: 0})
}

func (s *Server) handlePriceCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "prices", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		ProductID string  `json:"productId"`
		Amount    float64 `json:"amount"`
		Currency  string  `json:"currency"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.ProductID == "" || input.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "productId and amount are required")
		return
	}
	if _, ok := s.store.GetProduct(input.ProductID); !ok {
		writeError(w, http.StatusBadRequest, "validation_failed", "product not found")
		return
	}
	created, err := s.store.CreatePrice(identity.TenantID, input.ProductID, input.Amount, input.Currency)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create price")
		return
	}
	s.writeAudit(identity, "price.created", "prices", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handlePriceGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "prices", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	price, ok := s.store.GetPrice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "price not found")
		return
	}
	if price.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, price)
}

func (s *Server) handlePriceUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "prices", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	price, ok := s.store.GetPrice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "price not found")
		return
	}
	if price.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		ProductID string  `json:"productId"`
		Amount    float64 `json:"amount"`
		Currency  string  `json:"currency"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.ProductID == "" || input.Amount <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "productId and amount are required")
		return
	}
	price.ProductID = input.ProductID
	price.Amount = input.Amount
	price.Currency = input.Currency
	price.UpdatedAt = time.Now()
	s.store.UpdatePrice(price)
	s.writeAudit(identity, "price.updated", "prices", price.ID)
	writeJSON(w, http.StatusOK, price)
}

func (s *Server) handlePriceDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "prices", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	price, ok := s.store.GetPrice(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "price not found")
		return
	}
	if price.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeletePrice(id) {
		writeError(w, http.StatusNotFound, "not_found", "price not found")
		return
	}
	s.writeAudit(identity, "price.deleted", "prices", id)
	writeJSON(w, http.StatusNoContent, nil)
}
