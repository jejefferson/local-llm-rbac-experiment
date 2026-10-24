package rbac

import (
	"net/http"
	"strings"
)

// principalFor is the per-request caller, fully resolved server-side.
type callContext struct {
	token  string
	tenant string
	user   string
	role   Role
	issuer string
}

// bearerToken extracts the opaque token from the Authorization header. It
// accepts both "Bearer <t>" and a bare token, but nothing else. The token
// carries no decodable identity; only the store map knows what it means.
func bearerToken(h http.Header) (string, bool) {
	raw := h.Get("Authorization")
	if strings.EqualFold(raw, "") && raw == "" {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	pref := "Bearer "
	if len(raw) >= len(pref) && strings.EqualFold(raw[:len(pref)], pref) {
		raw = strings.TrimSpace(raw[len(pref):])
	}
	// Reject tokens with embedded whitespace / newlines.
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", false
	}
	return raw, true
}

// resolveIdentity authenticates the request by looking up the opaque token and
// resolving the caller's role from the live membership table. Identity comes
// ONLY from the token; role/userId are never read from headers, query, or body.
func (s *Server) resolveIdentity(r *http.Request) (callContext, *apiError) {
	token, ok := bearerToken(r.Header)
	if !ok {
		return callContext{}, errUnauthorized
	}
	rec, ok := s.store.ResolveToken(token)
	if !ok {
		// Unknown token: do not disclose why.
		return callContext{}, errUnauthorized
	}
	// Tenant is fixed by the token, not by any client header, so a caller cannot
	// move into a tenant they are not a token-holder for, nor impersonate.
	tenant := rec.Tenant
	role := s.store.roleFor(tenant, rec.UserID)
	return callContext{
		token:  token,
		tenant: tenant,
		user:   rec.UserID,
		role:   role,
		issuer: rec.IssuedBy,
	}, nil
}

// asPrincipal adapts a callContext to the principal the store expects, with the
// role resolved live (the store re-checks under its lock for mutations).
func (c callContext) asPrincipal() principal {
	return principal{UserID: c.user, Role: c.role}
}

// ensureTenantMembership reports whether the caller is a member of the tenant
// bound to their token. A non-member caller cannot act on the tenant.
func (c callContext) ensureTenantMembership() *apiError {
	if c.role == RoleNone {
		return newErr(statusForbidden, errCodeForbidden, "no membership in tenant "+c.tenant)
	}
	return nil
}
