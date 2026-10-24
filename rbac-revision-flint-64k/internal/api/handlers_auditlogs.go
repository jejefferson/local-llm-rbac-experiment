package api

import (
	"net/http"

	"rbac/internal/model"
	"rbac/internal/rbac"
)

func (s *Server) handleAuditLogsList(w http.ResponseWriter, r *http.Request) {
	identity := s.currentIdentity(r)
	if !rbac.Can(identity.Role, "audit-logs", rbac.ActionRead) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return
	}
	q := r.URL.Query()
	actor := q.Get("actor")
	action := q.Get("action")
	resource := q.Get("resource")
	limit, offset := parsePagination(r)
	logs, total, err := s.store.ListAuditLogs(identity.TenantID, actor, action, resource, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list audit logs")
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[model.AuditLog]{Data: logs, Total: total, Limit: limit, Offset: offset})
}
