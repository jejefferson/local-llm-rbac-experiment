package api

import (
	"net/http"
	"strings"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

type createProductInput struct {
	SKU         string  `json:"sku"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	Currency    string  `json:"currency"`
}

func (s *Server) handleProductsList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "products", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query().Get("q")
	limit, offset := parsePagination(r)
	products, total, err := s.store.ListProducts(identity.TenantID, q, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list products")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.Product]{Data: products, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleProductCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "products", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input createProductInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "product name is required")
		return
	}
	if strings.TrimSpace(input.SKU) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "product sku is required")
		return
	}
	if input.Price <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "product price must be positive")
		return
	}
	if input.Currency == "" {
		input.Currency = "USD"
	}
	created, err := s.store.CreateProduct(identity.TenantID, input.SKU, input.Name, input.Price, input.Currency, input.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create product")
		return
	}
	s.writeAudit(identity, "product.created", "products", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleProductGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "products", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	product, ok := s.store.GetProduct(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "product not found")
		return
	}
	if product.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, product)
}

func (s *Server) handleProductUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "products", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	product, ok := s.store.GetProduct(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "product not found")
		return
	}
	if product.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input createProductInput
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "product name is required")
		return
	}
	if strings.TrimSpace(input.SKU) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "product sku is required")
		return
	}
	if input.Price <= 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "product price must be positive")
		return
	}
	if input.Currency == "" {
		input.Currency = "USD"
	}
	product.SKU = input.SKU
	product.Name = input.Name
	product.Description = input.Description
	product.Price = input.Price
	product.Currency = input.Currency
	product.UpdatedAt = time.Now()
	s.store.UpdateProduct(product)
	s.writeAudit(identity, "product.updated", "products", product.ID)
	writeJSON(w, http.StatusOK, product)
}

func (s *Server) handleProductDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "products", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	product, ok := s.store.GetProduct(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "product not found")
		return
	}
	if product.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteProduct(id) {
		writeError(w, http.StatusNotFound, "not_found", "product not found")
		return
	}
	s.writeAudit(identity, "product.deleted", "products", id)
	writeJSON(w, http.StatusNoContent, nil)
}
