package rbac

import (
	"encoding/json"
	"io"
	"net/http"
)

// ListEnvelope is the uniform shape returned by list endpoints.
type ListEnvelope struct {
	Items   any  `json:"items"`
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// handleHealth is a public liveness/readiness probe.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "only GET is allowed"))
		return
	}
	writeJSON(w, statusOK, map[string]any{"status": "ok"})
}

// body decodes a JSON request body into a map. Numbers are preserved as
// json.Number via a UseNumber decoder. A non-object body yields a 400.
func (s *Server) body(r *http.Request, out *map[string]any) *apiError {
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		if err == io.EOF {
			return newErr(statusBadRequest, errCodeBadRequest, "empty request body")
		}
		return newErr(statusBadRequest, errCodeBadRequest, "invalid JSON body")
	}
	// Reject unexpected trailing non-whitespace content.
	if dec.More() {
		return newErr(statusBadRequest, errCodeBadRequest, "multiple JSON values in body")
	}
	return nil
}

// handleResource dispatches GET/POST/PATCH/PUT/DELETE for a resource, with or
// without a path id. The store re-checks authorization under its lock.
func (s *Server) handleResource(w http.ResponseWriter, r *http.Request, cc callContext, resource, id string, hasID bool) {
	switch r.Method {
	case http.MethodGet:
		if hasID {
			s.getResource(w, r, cc, resource, id)
			return
		}
		s.listResource(w, r, cc, resource)
		return
	case http.MethodPost:
		if hasID {
			writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "create does not accept a path id"))
			return
		}
		s.createResource(w, r, cc, resource)
	case http.MethodPatch, http.MethodPut:
		if !hasID {
			writeError(w, newErr(statusBadRequest, errCodeBadRequest, "update requires a path id"))
			return
		}
		full := r.Method == http.MethodPut
		s.updateResource(w, r, cc, resource, id, full)
	case http.MethodDelete:
		if !hasID {
			writeError(w, newErr(statusBadRequest, errCodeBadRequest, "delete requires a path id"))
			return
		}
		s.deleteResource(w, r, cc, resource, id)
	default:
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "method not allowed"))
	}
}

func (s *Server) getResource(w http.ResponseWriter, r *http.Request, cc callContext, resource, id string) {
	// audit-logs has no single-object read; reject early as 405.
	if resource == "audit-logs" {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "audit-logs list only, no single-object read"))
		return
	}
	actor := cc.asPrincipal()
	rec, status := s.store.GetRecord(resource, cc.tenant, id, actor)
	if status != 0 {
		writeError(w, errFromStatus(status, "record not found or access denied"))
		return
	}
	writeJSON(w, statusOK, rec)
}

func (s *Server) listResource(w http.ResponseWriter, r *http.Request, cc callContext, resource string) {
	actor := cc.asPrincipal()
	cfg := parsePageFilter(r.URL.Query())
	if cfg.Page.Limit < 0 || cfg.Page.Offset < 0 {
		writeError(w, newErr(statusBadRequest, errCodeBadRequest, "limit/offset must be non-negative integers"))
		return
	}
	if resource == "audit-logs" {
		if allow, _ := canAccess("audit-logs", cc.role, VerbRead); !allow {
			writeError(w, newErr(statusForbidden, errCodeForbidden, "forbidden"))
			return
		}
		items, p := s.store.ListAudit(cc.tenant, cfg.Page)
		writeJSON(w, statusOK, listEnvelopeFor(items, p))
		return
	}
	items, status, p := s.store.ListRecords(resource, cc.tenant, actor, cfg.Filter, cfg.Page)
	if status != 0 {
		writeError(w, errFromStatus(status, "access denied or not found"))
		return
	}
	writeJSON(w, statusOK, listEnvelopeFor(items, p))
}

func (s *Server) createResource(w http.ResponseWriter, r *http.Request, cc callContext, resource string) {
	if resource == "audit-logs" {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "audit-logs are append-only"))
		return
	}
	actor := cc.asPrincipal()
	var in map[string]any
	if berr := s.body(r, &in); berr != nil {
		writeError(w, berr)
		return
	}
	// The tenant is fixed by the token; reject any client-supplied tenant.
	delete(in, "tenant")
	// id/createdAt/updatedAt are server-assigned.
	delete(in, "id")
	delete(in, "createdAt")
	delete(in, "updatedAt")

	rec, status := s.store.CreateRecord(resource, cc.tenant, actor, in)
	if status != 0 {
		writeError(w, errFromStatus(status, "could not create record"))
		return
	}
	writeJSON(w, statusCreated, rec)
}

func (s *Server) updateResource(w http.ResponseWriter, r *http.Request, cc callContext, resource, id string, full bool) {
	if resource == "audit-logs" {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "audit-logs are read-only"))
		return
	}
	actor := cc.asPrincipal()
	if full {
		var in map[string]any
		if berr := s.body(r, &in); berr != nil {
			writeError(w, berr)
			return
		}
		// Immutable core fields.
		delete(in, "tenant")
		delete(in, "id")
		delete(in, "createdAt")
		delete(in, "updatedAt")
		delete(in, "owner")
		rec, status := s.store.UpdateRecord(resource, cc.tenant, id, actor, in, true)
		if status != 0 {
			writeError(w, errFromStatus(status, "could not update record"))
			return
		}
		writeJSON(w, statusOK, rec)
		return
	}

	var in map[string]any
	if berr := s.body(r, &in); berr != nil {
		writeError(w, berr)
		return
	}
	// PATCH must never carry immutable core fields.
	for _, k := range []string{"tenant", "id", "createdAt", "updatedAt"} {
		delete(in, k)
	}
	rec, status := s.store.UpdateRecord(resource, cc.tenant, id, actor, in, false)
	if status != 0 {
		writeError(w, errFromStatus(status, "could not update record"))
		return
	}
	writeJSON(w, statusOK, rec)
}

func (s *Server) deleteResource(w http.ResponseWriter, r *http.Request, cc callContext, resource, id string) {
	if resource == "audit-logs" {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "audit-logs cannot be deleted"))
		return
	}
	actor := cc.asPrincipal()
	status, deleted := s.store.DeleteRecord(resource, cc.tenant, id, actor)
	if status != 0 {
		writeError(w, errFromStatus(status, "could not delete record"))
		return
	}
	// 204 with an empty body.
	w.WriteHeader(statusNoContent)
	_ = deleted
}

// listEnvelopeFor builds the public list envelope from a Page carrying the
// normalized pagination fields.
func listEnvelopeFor(items any, p Page) ListEnvelope {
	return ListEnvelope{
		Items:   items,
		Total:   p.PageInfo.Total,
		Limit:   p.Limit,
		Offset:  p.Offset,
		HasMore: p.PageInfo.HasMore,
	}
}

// ---- member management (admin-only) --------------------------------------

// handleMembersList handles GET (list) and POST (add) on /api/v1/members.
func (s *Server) handleMembersList(w http.ResponseWriter, r *http.Request, cc callContext) {
	switch r.Method {
	case http.MethodGet:
		actor := cc.asPrincipal()
		cfg := parsePageFilter(r.URL.Query())
		if cfg.Page.Limit < 0 || cfg.Page.Offset < 0 {
			writeError(w, newErr(statusBadRequest, errCodeBadRequest, "limit/offset must be non-negative integers"))
			return
		}
		members, p, status := s.store.ListMembers(cc.tenant, actor, cfg.Page)
		if status != 0 {
			writeError(w, errFromStatus(status, "forbidden"))
			return
		}
		writeJSON(w, statusOK, ListEnvelope{Items: members, Total: p.PageInfo.Total, Limit: p.Limit, Offset: p.Offset, HasMore: p.PageInfo.HasMore})
	case http.MethodPost:
		s.addMember(w, r, cc)
	default:
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "method not allowed for members"))
	}
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request, cc callContext) {
	var in map[string]any
	if berr := s.body(r, &in); berr != nil {
		writeError(w, berr)
		return
	}
	user, _ := in["user"].(string)
	roleStr, _ := in["role"].(string)
	if user == "" || roleStr == "" {
		writeError(w, newErr(statusBadRequest, errCodeBadRequest, "user and role are required"))
		return
	}
	m, status := s.store.AddMember(cc.tenant, user, roleStr, cc.asPrincipal(), "")
	if status != 0 {
		writeError(w, errFromStatus(status, "could not add member"))
		return
	}
	writeJSON(w, statusCreated, m)
}

// handleMembersOne handles GET (read), PATCH (promote/demote), DELETE (revoke).
func (s *Server) handleMembersOne(w http.ResponseWriter, r *http.Request, cc callContext, id string) {
	// id is the member (user) within the tenant.
	user := id
	switch r.Method {
	case http.MethodPatch, http.MethodPut:
		s.updateMember(w, r, cc, user)
	case http.MethodDelete:
		status, deleted := s.store.RemoveMember(cc.tenant, user, cc.asPrincipal())
		if status != 0 {
			writeError(w, errFromStatus(status, "could not remove member"))
			return
		}
		w.WriteHeader(statusNoContent)
		_ = deleted
	case http.MethodGet:
		// Read a single member requires admin.
		members, _, status := s.store.ListMembers(cc.tenant, cc.asPrincipal(), Page{})
		if status != 0 {
			writeError(w, errFromStatus(status, "forbidden"))
			return
		}
		for _, m := range members {
			if m.User == user {
				writeJSON(w, statusOK, m)
				return
			}
		}
		writeError(w, newErr(statusNotFound, errCodeNotFound, "member not found"))
	default:
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "method not allowed for member"))
	}
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request, cc callContext, user string) {
	var in map[string]any
	if berr := s.body(r, &in); berr != nil {
		writeError(w, berr)
		return
	}
	roleStr, _ := in["role"].(string)
	if roleStr == "" {
		writeError(w, newErr(statusBadRequest, errCodeBadRequest, "role is required"))
		return
	}
	m, status := s.store.UpdateMember(cc.tenant, user, roleStr, cc.asPrincipal())
	if status != 0 {
		writeError(w, errFromStatus(status, "could not update member"))
		return
	}
	writeJSON(w, statusOK, m)
}

// ---- nested routes (child-of-order) --------------------------------------

// handleNested handles GET /api/v1/orders/{id}/{child} where child is one of
// payments, refunds, invoices. It enforces read on the parent order and read
// on the child resource, and applies tenant isolation.
func (s *Server) handleNested(w http.ResponseWriter, r *http.Request, cc callContext, segs []string) {
	if r.Method != http.MethodGet {
		writeError(w, newErr(statusMethodNotAllowed, errCodeMethodNotAllowed, "nested collection supports GET only"))
		return
	}
	parentResource, parentID, childResource := segs[0], segs[1], segs[2]
	actor := cc.asPrincipal()

	// The parent order must be readable (403/404 otherwise).
	if _, status := s.store.GetRecord(parentResource, cc.tenant, parentID, actor); status != 0 {
		writeError(w, errFromStatus(status, "parent order not found or access denied"))
		return
	}
	// The child resource must be readable.
	allow, _ := canAccess(childResource, cc.role, VerbRead)
	if !allow {
		writeError(w, newErr(statusForbidden, errCodeForbidden, "forbidden"))
		return
	}
	cfg := parsePageFilter(r.URL.Query())
	if cfg.Page.Limit < 0 || cfg.Page.Offset < 0 {
		writeError(w, newErr(statusBadRequest, errCodeBadRequest, "limit/offset must be non-negative integers"))
		return
	}
	items, status, p := s.store.ListRecords(childResource, cc.tenant, actor, Filter{Parent: parentID}, cfg.Page)
	if status != 0 {
		writeError(w, errFromStatus(status, "forbidden"))
		return
	}
	writeJSON(w, statusOK, listEnvelopeFor(items, p))
}
