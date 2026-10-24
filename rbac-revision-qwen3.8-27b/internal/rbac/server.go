package rbac

import (
	"net/http"
	"strings"
)

// apiPrefix is the path prefix for all protected endpoints.
const apiPrefix = "/api/v1/"

// Server is the HTTP front end. It is the single entry point; the store holds
// the authoritative state and all authorization decisions.
type Server struct {
	store *Store
}

// NewServer builds a Server backed by store.
func NewServer(store *Store) *Server {
	return &Server{store: store}
}

// Handler returns the root http.Handler, wired with the documented precedence:
//
//  1. public endpoints need no auth
//  2. unknown/invalid token               -> 401
//  3. no membership in the token's tenant -> 403
//  4. unknown resource type               -> 404
//  5. HTTP method not permitted for anyone-> 405
//  6. resource/object not found in tenant  -> 404
//  7. role lacks the verb / ownership /    -> 403
//     tenant-isolation / last-admin rule   -> 403 or 409
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
}

// Store exposes the underlying store (used to mint tokens in tests/seed).
func (s *Server) Store() *Store { return s.store }

// ServeHTTP is the root dispatcher.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Public endpoints.
	if path := strings.Trim(r.URL.Path, "/"); path == "" || path == "health" || path == "healthz" {
		s.handleHealth(w, r)
		return
	}

	// Only accept the api prefix; anything else is a 404 (but we still require a
	// valid token first so unauthenticated enumeration of paths is prevented).
	if !strings.HasPrefix(r.URL.Path, apiPrefix) && !isAPIRootPath(r.URL.Path) {
		// Reject with 401 to avoid leaking which paths exist.
		writeError(w, errUnauthorized)
		return
	}

	// 2. authenticate.
	cc, aerr := s.resolveIdentity(r)
	if aerr != nil {
		writeError(w, aerr)
		return
	}

	// 3. membership in the token's tenant.
	if mErr := cc.ensureTenantMembership(); mErr != nil {
		writeError(w, mErr)
		return
	}

	// Route within the api prefix.
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, apiPrefix), "/")
	segs := splitPath(rest)
	if len(segs) == 0 {
		writeError(w, newErr(statusNotFound, errCodeNotFound, "unknown resource"))
		return
	}

	switch {
	case len(segs) == 1 && segs[0] == "members":
		s.handleMembersList(w, r, cc)
		return
	case len(segs) == 2 && segs[0] == "members":
		s.handleMembersOne(w, r, cc, segs[1])
		return
	case isNestedRoute(segs):
		s.handleNested(w, r, cc, segs)
		return
	case len(segs) == 1:
		// list or create on a resource
		if !IsKnownResource(segs[0]) {
			writeError(w, newErr(statusNotFound, errCodeNotFound, "unknown resource type"))
			return
		}
		if status, ok := s.checkMethodUnion(segs[0], r.Method); !ok {
			writeError(w, newErr(status, errCodeMethodNotAllowed, "method not allowed for resource"))
			return
		}
		s.handleResource(w, r, cc, segs[0], "", false)
		return
	case len(segs) == 2:
		resource, id := segs[0], segs[1]
		if !IsKnownResource(resource) {
			writeError(w, newErr(statusNotFound, errCodeNotFound, "unknown resource type"))
			return
		}
		if status, ok := s.checkMethodUnion(resource, r.Method); !ok {
			writeError(w, newErr(status, errCodeMethodNotAllowed, "method not allowed for resource"))
			return
		}
		s.handleResource(w, r, cc, resource, id, true)
		return
	default:
		writeError(w, newErr(statusNotFound, errCodeNotFound, "unknown resource"))
	}
}

// isAPIRootPath reports whether a path is "/api/v1" (the base without trailing
// slash) so the trim/prefix logic is forgiving.
func isAPIRootPath(p string) bool {
	return p == apiPrefix[:len(apiPrefix)-1] || p == apiPrefix || p == "/api/v1"
}

// splitPath splits a possibly empty path into non-empty segments.
func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	raw := strings.Split(p, "/")
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// checkMethodUnion checks the HTTP method maps to a verb and that the verb is in
// the union of verbs allowed for ANY role on the resource. Returns (status, ok);
// ok=false means the method is not allowed for anyone (405).
func (s *Server) checkMethodUnion(resource, method string) (int, bool) {
	verb, ok := verbForMethod(method)
	if !ok {
		return statusMethodNotAllowed, false
	}
	verbs, known := unionVerbs(resource)
	if !known {
		return statusNotFound, false
	}
	if !verbs.Allows(verb) {
		return statusMethodNotAllowed, false
	}
	return statusOK, true
}

// verbForMethod maps an HTTP method to a resource verb.
func verbForMethod(method string) (Verb, bool) {
	switch method {
	case http.MethodGet:
		return VerbRead, true
	case http.MethodPost:
		return VerbCreate, true
	case http.MethodPatch, http.MethodPut:
		return VerbUpdate, true
	case http.MethodDelete:
		return VerbDelete, true
	default:
		return 0, false
	}
}

// isNestedRoute reports whether segs describe a nested child-of-order route.
func isNestedRoute(segs []string) bool {
	if len(segs) != 3 {
		return false
	}
	if segs[0] != "orders" {
		return false
	}
	switch segs[2] {
	case "payments", "refunds", "invoices":
		return true
	default:
		return false
	}
}
