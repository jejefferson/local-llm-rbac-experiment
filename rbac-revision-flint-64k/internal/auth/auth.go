// Package auth resolves bearer tokens into tenant user identities.
package auth

import (
	"errors"
	"net/http"
	"strings"

	"rbac/internal/rbac"
	"rbac/internal/store"
)

var ErrUnauthorized = errors.New("unauthorized")

// Identity is the server-side resolved principal of an authenticated request.
type Identity struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	Role     string `json:"role"`
}

// Auth validates bearer tokens against server-side issued fixtures/memberships.
type Auth struct {
	store *store.Store
}

func New(s *store.Store) *Auth {
	return &Auth{store: s}
}

// Authenticate extracts and validates the bearer token from the request.
func (a *Auth) Authenticate(r *http.Request) (*Identity, error) {
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return nil, ErrUnauthorized
	}
	token := parts[1]
	tenantID, userID, ok := a.store.LookupToken(token)
	if !ok {
		return nil, ErrUnauthorized
	}
	role, ok := a.store.GetMemberRole(tenantID, userID)
	if !ok || !rbac.ValidRole(role) {
		return nil, ErrUnauthorized
	}
	return &Identity{TenantID: tenantID, UserID: userID, Role: role}, nil
}
