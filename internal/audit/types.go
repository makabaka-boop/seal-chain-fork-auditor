// Package audit verifies evidence-seal event chains independently of the
// order in which events were uploaded from offline workstations.
package audit

// Event is a single evidence-seal record as registered by a workstation.
// The root event has an empty ParentID and a PrevDigest of ZeroDigest.
type Event struct {
	ID         string `json:"id"`
	ParentID   string `json:"parentId"`
	Payload    string `json:"payload"`
	PrevDigest string `json:"prevDigest"`
	Digest     string `json:"digest"`
}

// ErrorCode classifies a chain-structure or digest anomaly.
type ErrorCode string

const (
	CodeCycle               ErrorCode = "CYCLE"                 // event sits on a parent-reference cycle
	CodeDigestMismatch      ErrorCode = "DIGEST_MISMATCH"       // declared digest != recomputed digest
	CodeDuplicateID         ErrorCode = "DUPLICATE_ID"          // id appears more than once
	CodeFork                ErrorCode = "FORK"                  // a predecessor has more than one child
	CodeInvalidDigestFormat ErrorCode = "INVALID_DIGEST_FORMAT" // digest field is not 64 lowercase hex chars
	CodeMissingParent       ErrorCode = "MISSING_PARENT"        // parentId references no known event
	CodeMultipleRoots       ErrorCode = "MULTIPLE_ROOTS"        // more than one event has an empty parentId
	CodeNoRoot              ErrorCode = "NO_ROOT"               // no event has an empty parentId
	CodePrevDigestMismatch  ErrorCode = "PREV_DIGEST_MISMATCH"  // prevDigest != predecessor's declared digest
)

// AuditError describes one anomaly, attributed to an event where applicable.
type AuditError struct {
	Code    ErrorCode `json:"code"`
	EventID string    `json:"eventId,omitempty"`
	Message string    `json:"message"`
}

// Result is the outcome of auditing a set of events. Chain and TailDigest
// are only populated when the events form exactly one complete, intact
// chain; Errors is only populated otherwise.
type Result struct {
	Valid      bool         `json:"valid"`
	EventCount int          `json:"eventCount"`
	Chain      []string     `json:"chain,omitempty"`
	TailDigest string       `json:"tailDigest,omitempty"`
	Errors     []AuditError `json:"errors,omitempty"`
}
