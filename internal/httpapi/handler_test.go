package httpapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"evidence-audit/internal/audit"
	"evidence-audit/internal/httpapi"
)

func buildChain(t *testing.T, n int) []audit.Event {
	t.Helper()
	events := make([]audit.Event, 0, n)
	prev, parent := audit.ZeroDigest, ""
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ev-%03d", i)
		payload := fmt.Sprintf("sealed evidence bag %d", i)
		digest, err := audit.ComputeDigest(id, prev, payload)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, audit.Event{
			ID:         id,
			ParentID:   parent,
			Payload:    payload,
			PrevDigest: prev,
			Digest:     digest,
		})
		prev, parent = digest, id
	}
	return events
}

func bodyOf(t *testing.T, events []audit.Event) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func do(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	httpapi.NewHandler().ServeHTTP(rec, req)
	return rec
}

func decodeResult(t *testing.T, rec *httptest.ResponseRecorder) audit.Result {
	t.Helper()
	var res audit.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not a valid audit result: %v\nbody: %s", err, rec.Body)
	}
	return res
}

func TestAuditEndpointAcceptsShuffledValidChain(t *testing.T) {
	events := buildChain(t, 32)
	r := rand.New(rand.NewPCG(1, 2))
	r.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })

	rec := do(t, http.MethodPost, "/audit", bodyOf(t, events))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	res := decodeResult(t, rec)
	if !res.Valid {
		t.Fatalf("expected valid chain, got %+v", res.Errors)
	}
	if len(res.Chain) != 32 || res.Chain[0] != "ev-000" || res.Chain[31] != "ev-031" {
		t.Fatalf("unexpected chain: %v", res.Chain)
	}
	if res.TailDigest == "" {
		t.Fatal("tail digest missing")
	}
}

func TestAuditEndpointReportsCorruption(t *testing.T) {
	events := buildChain(t, 6)
	events[3].Payload = "tampered in transit"

	rec := do(t, http.MethodPost, "/audit", bodyOf(t, events))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	res := decodeResult(t, rec)
	if res.Valid {
		t.Fatal("expected invalid result")
	}
	if len(res.Errors) != 1 || res.Errors[0].Code != audit.CodeDigestMismatch || res.Errors[0].EventID != "ev-003" {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}
	if res.Chain != nil || res.TailDigest != "" {
		t.Fatal("chain and tailDigest must be omitted when the audit fails")
	}
}

func TestAuditEndpointValidationFailures(t *testing.T) {
	zero := audit.ZeroDigest
	validEvent := fmt.Sprintf(`{"id":"ev-000","parentId":"","payload":"p","prevDigest":%q,"digest":%q}`, zero, zero)

	cases := map[string]string{
		"empty body":              "",
		"malformed json":          `{"events": [`,
		"not an object":           `[]`,
		"missing events":          `{}`,
		"unknown top-level field": `{"events": [], "station": "WS-1"}`,
		"empty events":            `{"events": []}`,
		"events null":             `{"events": null}`,
		"missing digest":          `{"events": [{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `"}]}`,
		"missing id":              `{"events": [{"parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
		"empty id":                `{"events": [{"id":"","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
		"uppercase digest":        `{"events": [{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + strings.Repeat("AB", 32) + `"}]}`,
		"short prevDigest":        `{"events": [{"id":"a","parentId":"","payload":"p","prevDigest":"abc","digest":"` + zero + `"}]}`,
		"non-hex digest":          `{"events": [{"id":"a","parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + strings.Repeat("zz", 32) + `"}]}`,
		"duplicate ids": `{"events": [` + validEvent + `,` +
			fmt.Sprintf(`{"id":"ev-000","parentId":"x","payload":"p","prevDigest":%q,"digest":%q}`, zero, zero) + `]}`,
		"trailing data":    `{"events": [` + validEvent + `]} {"extra": true}`,
		"wrong field type": `{"events": [{"id": 1,"parentId":"","payload":"p","prevDigest":"` + zero + `","digest":"` + zero + `"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := do(t, http.MethodPost, "/audit", []byte(body))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
			}
			var er struct {
				Error struct {
					Code    string   `json:"code"`
					Details []string `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
				t.Fatalf("error response is not JSON: %v", err)
			}
			if er.Error.Code != "VALIDATION_FAILED" {
				t.Fatalf("error code = %q, want VALIDATION_FAILED", er.Error.Code)
			}
		})
	}
}

func TestAuditEndpointRejectsTooManyEvents(t *testing.T) {
	rec := do(t, http.MethodPost, "/audit", bodyOf(t, buildChain(t, 2001)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body: %s", rec.Code, rec.Body)
	}
}

func TestAuditEndpointAcceptsExactlyMaxEvents(t *testing.T) {
	rec := do(t, http.MethodPost, "/audit", bodyOf(t, buildChain(t, 2000)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if res := decodeResult(t, rec); !res.Valid || len(res.Chain) != 2000 {
		t.Fatalf("expected a valid 2000-event chain, got %+v", res.Errors)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rec := do(t, http.MethodGet, "/audit", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !slices.Contains(strings.Split(allow, ", "), "POST") && allow != "POST" {
		t.Fatalf("Allow header = %q, want POST", allow)
	}
}

func TestHealthz(t *testing.T) {
	rec := do(t, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
