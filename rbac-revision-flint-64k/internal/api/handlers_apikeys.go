package api

import (
	"net/http"
	"time"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleApiKeysList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "api-keys", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	keys, total, err := s.store.ListApiKeys(identity.TenantID, 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list api keys")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.ApiKey]{Data: keys, Total: total, Limit: 100, Offset: 0})
}

func (s *Server) handleApiKeyCreate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "api-keys", rbac.ActionCreate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if input.Name == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "name is required")
		return
	}
	newID := s.store.NextID("key", identity.TenantID)
	created, err := s.store.CreateApiKey(identity.TenantID, input.Name, "keyid_"+newID, "sk_live_"+newID, "active")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create api key")
		return
	}
	s.writeAudit(identity, "api_key.created", "api-keys", created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleApiKeyGet(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "api-keys", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	key, ok := s.store.GetApiKey(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	if key.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) handleApiKeyUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "api-keys", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	key, ok := s.store.GetApiKey(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	if key.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	var input struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	key.Name = input.Name
	key.Status = input.Status
	key.UpdatedAt = time.Now()
	s.store.UpdateApiKey(key)
	s.writeAudit(identity, "api_key.updated", "api-keys", key.ID)
	writeJSON(w, http.StatusOK, key)
}

func (s *Server) handleApiKeyDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "api-keys", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	id := r.PathValue("id")
	key, ok := s.store.GetApiKey(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	if key.TenantID != identity.TenantID {
		writeError(w, http.StatusForbidden, "forbidden", "cross tenant access denied")
		return
	}
	if !s.store.DeleteApiKey(id) {
		writeError(w, http.StatusNotFound, "not_found", "api key not found")
		return
	}
	s.writeAudit(identity, "api_key.deleted", "api-keys", id)
	writeJSON(w, http.StatusNoContent, nil)
}
