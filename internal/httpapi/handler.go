// Package httpapi exposes the evidence-seal audit engine over net/http.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"evidence-audit/internal/audit"
)

const (
	// maxBodyBytes bounds the request body (32 MiB covers 2000 events with
	// ample room for payloads).
	maxBodyBytes = 32 << 20
	// maxEvents is the maximum number of events accepted per request.
	maxEvents = 2000
	// maxValidationDetails caps the per-field findings returned in one 422.
	maxValidationDetails = 50
)

// eventJSON mirrors the wire format; pointer fields distinguish a missing
// field (a 422 validation error) from an explicitly empty value.
type eventJSON struct {
	ID         *string `json:"id"`
	ParentID   *string `json:"parentId"`
	Payload    *string `json:"payload"`
	PrevDigest *string `json:"prevDigest"`
	Digest     *string `json:"digest"`
}

type requestJSON struct {
	Events []eventJSON `json:"events"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

// NewHandler returns the API routes: POST /audit and GET /healthz.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit", handleAudit)
	mux.HandleFunc("GET /healthz", handleHealthz)
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()

	var req requestJSON
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE",
				fmt.Sprintf("request body exceeds %d MiB", maxBodyBytes>>20), nil)
		case errors.Is(err, io.EOF):
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
				"request body must not be empty", nil)
		default:
			writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
				"request body is not valid JSON: "+err.Error(), nil)
		}
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"request body must contain a single JSON document", nil)
		return
	}

	events, details := validate(req)
	if len(details) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED",
			"request validation failed", details)
		return
	}

	writeJSON(w, http.StatusOK, audit.Audit(events))
}

// validate enforces the request contract (1..2000 events, unique ids, all
// fields present, digest fields in canonical form) and converts the wire
// representation into audit events.
func validate(req requestJSON) ([]audit.Event, []string) {
	var details []string
	if req.Events == nil {
		return nil, []string{"events: field is required"}
	}
	if len(req.Events) == 0 {
		return nil, []string{"events: must contain at least 1 event"}
	}
	if len(req.Events) > maxEvents {
		return nil, []string{fmt.Sprintf("events: must contain at most %d events, got %d", maxEvents, len(req.Events))}
	}

	seen := make(map[string]struct{}, len(req.Events))
	events := make([]audit.Event, 0, len(req.Events))
	for i, e := range req.Events {
		field := func(name string) string { return fmt.Sprintf("events[%d].%s", i, name) }

		missing := false
		require := func(ptr *string, name string) {
			if ptr == nil {
				details = append(details, field(name)+": field is required")
				missing = true
			}
		}
		require(e.ID, "id")
		require(e.ParentID, "parentId")
		require(e.Payload, "payload")
		require(e.PrevDigest, "prevDigest")
		require(e.Digest, "digest")
		if missing {
			continue
		}

		if *e.ID == "" {
			details = append(details, field("id")+": must not be empty")
		} else if _, dup := seen[*e.ID]; dup {
			details = append(details, field("id")+fmt.Sprintf(": duplicate event id %q", *e.ID))
		} else {
			seen[*e.ID] = struct{}{}
		}
		if !audit.IsDigestFormat(*e.PrevDigest) {
			details = append(details, field("prevDigest")+": must be 64 lowercase hexadecimal characters")
		}
		if !audit.IsDigestFormat(*e.Digest) {
			details = append(details, field("digest")+": must be 64 lowercase hexadecimal characters")
		}

		events = append(events, audit.Event{
			ID:         *e.ID,
			ParentID:   *e.ParentID,
			Payload:    *e.Payload,
			PrevDigest: *e.PrevDigest,
			Digest:     *e.Digest,
		})
	}

	if len(details) > maxValidationDetails {
		omitted := len(details) - maxValidationDetails
		details = append(details[:maxValidationDetails],
			fmt.Sprintf("... %d further validation error(s) omitted", omitted))
	}
	if len(details) > 0 {
		return nil, details
	}
	return events, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string, details []string) {
	writeJSON(w, status, errorResponse{Error: apiError{
		Code:    code,
		Message: message,
		Details: details,
	}})
}
