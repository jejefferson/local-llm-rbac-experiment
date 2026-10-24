package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"rbac/internal/auth"
	"rbac/internal/model"
)

// APIError describes an error response returned by the API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func errorf(status int, code string, message string) *APIError {
	return &APIError{StatusCode: status, Code: code, Message: message}
}

// ListResponse is the standard envelope for list endpoints.
type ListResponse[T any] struct {
	Data   []*T `json:"data"`
	Total  int  `json:"total"`
	Limit  int  `json:"limit"`
	Offset int  `json:"offset"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	if status == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// decodeJSON reads and decodes a JSON request body.
func decodeJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	return dec.Decode(dst)
}

// parsePagination reads the limit/offset query parameters.
func parsePagination(r *http.Request) (int, int) {
	q := r.URL.Query()
	limit := 20
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// writeAudit appends an audit log entry for an authorized action.
func (s *Server) writeAudit(identity *auth.Identity, action string, resource string, details string) {
	entry := &model.AuditLog{
		Base:     model.Base{ID: s.store.NextID("aud", identity.TenantID), TenantID: identity.TenantID, CreatedAt: time.Now()},
		Action:   action,
		Actor:    identity.UserID,
		Resource: resource,
		Details:  details,
	}
	s.store.AppendAudit(entry)
}
