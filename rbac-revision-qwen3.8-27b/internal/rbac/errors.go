package rbac

import (
	"encoding/json"
	"net/http"
)

// Canonical HTTP status codes used across the service.
const (
	statusOK               = http.StatusOK               // 200
	statusCreated          = http.StatusCreated          // 201
	statusNoContent        = http.StatusNoContent        // 204
	statusBadRequest       = http.StatusBadRequest       // 400
	statusUnauthorized     = http.StatusUnauthorized     // 401
	statusForbidden        = http.StatusForbidden        // 403
	statusNotFound         = http.StatusNotFound         // 404
	statusMethodNotAllowed = http.StatusMethodNotAllowed // 405
	statusConflict         = http.StatusConflict         // 409
)

// Error codes returned in the JSON error envelope.
const (
	errCodeBadRequest       = "bad_request"
	errCodeUnauthorized     = "unauthorized"
	errCodeForbidden        = "forbidden"
	errCodeNotFound         = "not_found"
	errCodeMethodNotAllowed = "method_not_allowed"
	errCodeConflict         = "conflict"
)

// apiError is an internal error carrying an HTTP status and a stable code.
type apiError struct {
	status  int
	code    string
	message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

// newErr builds an apiError.
func newErr(status int, code, message string) *apiError {
	return &apiError{status: status, code: code, message: message}
}

// Pre-built error constructors.
var (
	errBadRequest   = newErr(statusBadRequest, errCodeBadRequest, "invalid request")
	errUnauthorized = newErr(statusUnauthorized, errCodeUnauthorized, "missing or invalid bearer token")
	errForbidden    = newErr(statusForbidden, errCodeForbidden, "forbidden")
	errNotFound     = newErr(statusNotFound, errCodeNotFound, "not found")
	errConflict     = newErr(statusConflict, errCodeConflict, "conflict")
)

// pageConfig holds pagination + filtering options parsed from the query string.
type pageConfig struct {
	Filter Filter
	Page   Page
}

// Page carries pagination inputs (Limit/Offset) and, after a query, the
// computed total so it can be echoed back in the response.
type Page struct {
	Limit  int
	Offset int
	PageInfo
}

// PageInfo is the pagination metadata returned to clients.
type PageInfo struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// Filter holds optional list filters.
type Filter struct {
	Owner  string
	Status string
	Parent string
}

// principal is the authenticated caller passed to store methods. Its Role field
// is ADVISORY ONLY: store methods always re-derive the authoritative role from
// the live tenant membership table so that a stale or forged role can never
// grant access. UserID is the source of truth.
type principal struct {
	UserID string
	Role   Role // advisory; ignored by store methods
}

// jsonMarshalMap produces indented-free JSON for a map. Kept separate so record
// marshaling stays explicit.
func jsonMarshalMap(m map[string]any) ([]byte, error) {
	return json.Marshal(m)
}

// writeJSON writes a JSON body with the given status and content type.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes the standard error envelope:
//
//	{ "error": { "code": "...", "message": "..." } }
func writeError(w http.ResponseWriter, e *apiError) {
	env := map[string]any{
		"error": map[string]any{
			"code":    e.code,
			"message": e.message,
		},
	}
	writeJSON(w, e.status, env)
}

// ensureStatus maps a bare int status (returned by store methods) and a code to
// an apiError, for handlers that received only a status.
func ensureStatus(status int, msg string) *apiError {
	switch status {
	case statusNotFound:
		return newErr(statusNotFound, errCodeNotFound, msg)
	case statusForbidden:
		return newErr(statusForbidden, errCodeForbidden, msg)
	case statusBadRequest:
		return newErr(statusBadRequest, errCodeBadRequest, msg)
	case statusConflict:
		return newErr(statusConflict, errCodeConflict, msg)
	case statusUnauthorized:
		return newErr(statusUnauthorized, errCodeUnauthorized, msg)
	default:
		if status == 0 {
			return newErr(statusOK, "ok", "ok")
		}
		return newErr(status, http.StatusText(status), msg)
	}
}

// errFromStatus converts a store int status back into an apiError for handlers.
func errFromStatus(status int, msg string) *apiError {
	return ensureStatus(status, msg)
}
