package api

import (
	"net/http"

	"rbac/internal/rbac"
)

func (s *Server) handleMembersList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "members", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	members := s.store.ListMembers(identity.TenantID)
	writeJSON(w, http.StatusOK, members)
}

func (s *Server) handleMemberUpdate(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "members", rbac.ActionUpdate) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	if identity.Role != "admin" {
		writeError(w, http.StatusForbidden, "forbidden", "only admins can manage memberships")
		return
	}
	userID := r.PathValue("userId")
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request body")
		return
	}
	if !rbac.ValidRole(input.Role) {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid role")
		return
	}
	targetRole, ok := s.store.GetMemberRole(identity.TenantID, userID)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "member not found")
		return
	}
	if targetRole == "admin" && input.Role != "admin" && s.isLastAdmin(identity.TenantID, userID) {
		writeError(w, http.StatusBadRequest, "last_admin", "cannot demote the last tenant administrator")
		return
	}
	if !s.store.UpdateMemberRole(identity.TenantID, userID, input.Role) {
		writeError(w, http.StatusNotFound, "not_found", "member not found")
		return
	}
	s.writeAudit(identity, "member.updated", "members", userID)
	writeJSON(w, http.StatusOK, map[string]string{"tenantId": identity.TenantID, "userId": userID, "role": input.Role})
}

func (s *Server) handleMemberDelete(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "members", rbac.ActionDelete) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	userID := r.PathValue("userId")
	targetRole, ok := s.store.GetMemberRole(identity.TenantID, userID)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "member not found")
		return
	}
	if targetRole == "admin" && s.isLastAdmin(identity.TenantID, userID) {
		writeError(w, http.StatusBadRequest, "last_admin", "cannot remove the last tenant administrator")
		return
	}
	if !s.store.DeleteMember(identity.TenantID, userID) {
		writeError(w, http.StatusNotFound, "not_found", "member not found")
		return
	}
	s.writeAudit(identity, "member.deleted", "members", userID)
	writeJSON(w, http.StatusNoContent, nil)
}

// isLastAdmin reports whether the given user is the sole administrator of the tenant.
func (s *Server) isLastAdmin(tenantID string, userID string) bool {
	for _, m := range s.store.ListMembers(tenantID) {
		if m.Role == "admin" {
			return m.UserID == userID
		}
	}
	return false
}
