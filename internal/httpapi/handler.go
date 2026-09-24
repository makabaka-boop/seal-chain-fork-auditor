// Package httpapi exposes the evidence-seal audit service over net/http.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	"sealaudit/internal/audit"
)

const (
	minEvents = 1
	maxEvents = 2000
	// 2000 events of the documented shape stay far below this ceiling; it
	// only protects the parser from oversized or hostile request bodies.
	maxBodyBytes = 16 << 20
)

// Error codes for the 422 request-validation envelope. These are distinct from
// the chain-level audit.ErrorCode values.
const (
	codeMalformedJSON       = "MALFORMED_JSON"
	codeBodyTooLarge        = "BODY_TOO_LARGE"
	codeRequestInvalid      = "REQUEST_VALIDATION_FAILED"
	codeUnsupportedType     = "UNSUPPORTED_MEDIA_TYPE"
	codeInternalServerError = "INTERNAL_SERVER_ERROR"
)

// request is the documented request envelope.
type request struct {
	Events []*eventInput `json:"events"`
}

// eventInput uses pointers for required fields so that a missing or null field
// is distinguishable from an empty string.
type eventInput struct {
	ID         *string `json:"id"`
	ParentID   *string `json:"parentId"`
	Payload    *string `json:"payload"`
	PrevDigest *string `json:"prevDigest"`
	Digest     *string `json:"digest"`
}

// FieldError pinpoints one rejected field, indexed by the position of the event
// in the request array (0-based).
type FieldError struct {
	Index  *int   `json:"index,omitempty"`
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// invalidResponse is returned with HTTP 422 for every malformed or invalid
// request.
type invalidResponse struct {
	Code   string       `json:"code"`
	Error  string       `json:"error"`
	Fields []FieldError `json:"fields,omitempty"`
}

// NewMux builds the service's HTTP route tree.
func NewMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit", handleAudit)
	// Explicit method-less route so non-POST callers get 405 instead of being
	// swallowed by the not-found catch-all.
	mux.HandleFunc("/audit", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, invalidResponse{
			Code:  "METHOD_NOT_ALLOWED",
			Error: "use POST /audit",
		})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, invalidResponse{
			Code:  "NOT_FOUND",
			Error: "unknown route; use POST /audit",
		})
	})
	return mux
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/json" {
		// Tolerate absent charset; reject clearly non-JSON payloads.
		if media := mediaType(ct); media != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, invalidResponse{
				Code:  codeUnsupportedType,
				Error: "Content-Type must be application/json",
			})
			return
		}
	}

	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, readErr := io.ReadAll(body)
	if readErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(readErr, &maxErr) {
			writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
				Code:  codeBodyTooLarge,
				Error: "request body exceeds 16 MiB limit",
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "cannot read request body",
		})
		return
	}

	// JSON text must itself be valid UTF-8 (RFC 8259); Go's decoder would
	// otherwise silently replace invalid bytes with U+FFFD.
	if !utf8.Valid(raw) {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body must be valid UTF-8 JSON",
		})
		return
	}

	var req request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body is not a valid events document: " + truncate(err.Error()),
		})
		return
	}
	// Require a single JSON value: no trailing tokens or data.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:  codeMalformedJSON,
			Error: "request body must contain exactly one JSON object",
		})
		return
	}

	var fields []FieldError
	add := func(index int, field, reason string) {
		i := index
		fields = append(fields, FieldError{Index: &i, Field: field, Reason: reason})
	}
	addTop := func(field, reason string) {
		fields = append(fields, FieldError{Field: field, Reason: reason})
	}

	if req.Events == nil {
		addTop("events", "events is required and must be an array")
	} else if len(req.Events) < minEvents || len(req.Events) > maxEvents {
		addTop("events", "events must contain between 1 and 2000 items")
	} else {
		seen := make(map[string]struct{}, len(req.Events))
		for i, in := range req.Events {
			if in == nil {
				add(i, "event", "event must be a JSON object")
				continue
			}
			if in.ID == nil {
				add(i, "id", "id is required")
			} else if *in.ID == "" {
				add(i, "id", "id must not be empty")
			} else if len(*in.ID) > 0xffffffff {
				add(i, "id", "id length exceeds uint32 range")
			} else if _, dup := seen[*in.ID]; dup {
				add(i, "id", "id must be unique within the batch")
			} else {
				seen[*in.ID] = struct{}{}
			}
			// parentId marks the root when empty; any other value must
			// resolve to an event (checked by the auditor).
			if in.ParentID == nil {
				add(i, "parentId", "parentId is required (use an empty string for the root)")
			}
			if in.Payload == nil {
				add(i, "payload", "payload is required")
			} else if len(*in.Payload) > 0xffffffff {
				add(i, "payload", "payload length exceeds uint32 range")
			}
			if in.PrevDigest == nil {
				add(i, "prevDigest", "prevDigest is required")
			} else if !isHexDigest(*in.PrevDigest) {
				add(i, "prevDigest", "prevDigest must be 64 lowercase hexadecimal characters")
			}
			if in.Digest == nil {
				add(i, "digest", "digest is required")
			} else if !isHexDigest(*in.Digest) {
				add(i, "digest", "digest must be 64 lowercase hexadecimal characters")
			}
		}
	}

	if len(fields) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, invalidResponse{
			Code:   codeRequestInvalid,
			Error:  "request failed validation",
			Fields: fields,
		})
		return
	}

	events := make([]audit.Event, len(req.Events))
	for i, in := range req.Events {
		events[i] = audit.Event{
			ID:         *in.ID,
			ParentID:   *in.ParentID,
			Payload:    *in.Payload,
			PrevDigest: *in.PrevDigest,
			Digest:     *in.Digest,
		}
	}

	writeJSON(w, http.StatusOK, audit.Audit(events))
}

func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerHex {
			return false
		}
	}
	return true
}

func mediaType(contentType string) string {
	for i := 0; i < len(contentType); i++ {
		if contentType[i] == ';' {
			contentType = contentType[:i]
			break
		}
	}
	// Trim leading/trailing whitespace (e.g. "application/json; charset=utf-8").
	start, end := 0, len(contentType)
	for start < end && isSpace(contentType[start]) {
		start++
	}
	for end > start && isSpace(contentType[end-1]) {
		end--
	}
	return contentType[start:end]
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

func truncate(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
