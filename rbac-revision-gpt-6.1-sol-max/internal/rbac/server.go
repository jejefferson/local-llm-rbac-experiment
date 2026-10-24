package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maxBodyBytes = 1 << 20

type apiError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func badInput(message string) *apiError {
	return &apiError{http.StatusBadRequest, "invalid_request", message}
}

func notFound(message string) *apiError {
	return &apiError{http.StatusNotFound, "not_found", message}
}

func conflict(code, message string) *apiError {
	return &apiError{http.StatusConflict, code, message}
}

type response struct {
	status  int
	body    any
	headers map[string]string
}

func failure(err *apiError) response {
	return response{status: err.Status, body: map[string]any{"error": err}}
}

// Server is a self-contained, seeded HTTP API. It is safe for concurrent use.
// Identity fixtures are immutable; mutable memberships live in the store.
type Server struct {
	store      *store
	tokenUsers map[string]string
	users      map[string]bool
}

func (s *Server) authenticate(r *http.Request) (string, bool) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return "", false
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	userID, ok := s.tokenUsers[parts[1]]
	return userID, ok
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == "/health/" {
		if r.Method != http.MethodGet {
			result := failure(&apiError{405, "method_not_allowed", "unsupported HTTP method"})
			result.headers = map[string]string{"Allow": "GET"}
			writeResponse(w, result)
			return
		}
		writeResponse(w, response{status: 200, body: map[string]string{"status": "ok"}})
		return
	}
	userID, ok := s.authenticate(r)
	if !ok {
		result := failure(&apiError{401, "unauthenticated", "a valid bearer token is required"})
		result.headers = map[string]string{"WWW-Authenticate": `Bearer realm="rbac"`}
		writeResponse(w, result)
		return
	}
	path, ok := parseRoute(r.URL.EscapedPath())
	if !ok {
		writeResponse(w, failure(notFound("route not found")))
		return
	}
	a, allow := path.action(r.Method)
	var body map[string]any
	var bodyError *apiError
	if a == create || a == update {
		// Read bounded request data before taking a store lock. Authorization is
		// checked inside the lock before any validation error is exposed or any
		// data is changed, including if membership changed while reading the body.
		body, bodyError = readBody(w, r)
	}
	result := s.execute(path, userID, a, allow, r.Method, r.URL.RawQuery, body, bodyError)
	writeResponse(w, result)
}

func (s *Server) execute(path route, userID string, a action, allow, method, rawQuery string, body map[string]any, bodyError *apiError) response {
	if a == read || a == 0 {
		s.store.mu.RLock()
		defer s.store.mu.RUnlock()
	} else {
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
	}
	t := s.store.tenants[path.tenantID]
	if t == nil {
		return failure(notFound("tenant not found"))
	}
	r, member := t.Members[userID]
	if !member {
		return failure(&apiError{403, "forbidden", "tenant membership is required"})
	}
	if a == 0 {
		result := failure(&apiError{405, "method_not_allowed", "unsupported HTTP method"})
		result.headers = map[string]string{"Allow": allow}
		return result
	}
	if !allowed(r, path.resource, a) {
		return failure(&apiError{403, "forbidden", "this role cannot perform the requested action"})
	}
	if !path.parentsVisible(t, r, userID) {
		return failure(notFound("parent record not found"))
	}
	if path.resource == "members" {
		return s.members(t, path, userID, a, rawQuery, body, bodyError)
	}
	return s.resource(t, path, userID, r, a, method, rawQuery, body, bodyError)
}

func writeResponse(w http.ResponseWriter, result response) {
	w.Header().Set("Cache-Control", "no-store")
	for key, value := range result.headers {
		w.Header().Set(key, value)
	}
	if result.status == http.StatusNoContent {
		w.WriteHeader(result.status)
		return
	}
	data, err := json.Marshal(result.body)
	if err != nil {
		result.status = 500
		data = []byte(`{"error":{"code":"internal_error","message":"could not encode response"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(result.status)
	_, _ = w.Write(append(data, '\n'))
}

func readBody(w http.ResponseWriter, r *http.Request) (map[string]any, *apiError) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, &apiError{415, "unsupported_media_type", "Content-Type must be application/json"}
	}
	reader := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err == nil {
		if _, trailing := decoder.Token(); trailing != io.EOF {
			if trailing != nil {
				err = trailing
			} else {
				err = fmt.Errorf("expected one JSON object")
			}
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &apiError{413, "body_too_large", "request body exceeds 1 MiB"}
		}
		return nil, badInput("body must be one JSON object with unique keys")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, badInput("body must be a JSON object")
	}
	if len(object) == 0 {
		return nil, badInput("body must contain at least one field")
	}
	return object, nil
}

// A small token decoder rejects duplicate keys rather than silently choosing an
// identity, role, or foreign key from an ambiguous JSON document.
func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object key must be a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate key")
			}
			value, err := decodeValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("unclosed object")
		}
		return object, nil
	case json.Delim('['):
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("unclosed array")
		}
		return array, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, fmt.Errorf("unexpected delimiter")
	default:
		return token, nil
	}
}
