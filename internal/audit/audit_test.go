package audit_test

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"evidence-audit/internal/audit"
)

// buildChainFrom builds a valid chain of n events (ev-000 .. ev-(n-1)) whose
// root uses rootPrev as prevDigest. buildChain uses the canonical all-zero
// root prevDigest, so every check passes.
func buildChainFrom(t *testing.T, n int, rootPrev string) []audit.Event {
	t.Helper()
	events := make([]audit.Event, 0, n)
	prev, parent := rootPrev, ""
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ev-%03d", i)
		payload := fmt.Sprintf("sealed evidence bag %d", i)
		events = append(events, audit.Event{
			ID:         id,
			ParentID:   parent,
			Payload:    payload,
			PrevDigest: prev,
			Digest:     mustDigest(t, id, prev, payload),
		})
		prev, parent = events[i].Digest, id
	}
	return events
}

func buildChain(t *testing.T, n int) []audit.Event {
	t.Helper()
	return buildChainFrom(t, n, audit.ZeroDigest)
}

func mustDigest(t *testing.T, id, prevHex, payload string) string {
	t.Helper()
	d, err := audit.ComputeDigest(id, prevHex, payload)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	return d
}

// shuffle returns a copy of events in a deterministic pseudo-random order,
// simulating out-of-order uploads from independent workstations.
func shuffle(events []audit.Event, seed uint64) []audit.Event {
	out := slices.Clone(events)
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// errIndex groups error event ids by code, sorted, for set comparison.
func errIndex(res audit.Result) map[audit.ErrorCode][]string {
	m := map[audit.ErrorCode][]string{}
	for _, e := range res.Errors {
		m[e.Code] = append(m[e.Code], e.EventID)
	}
	for _, ids := range m {
		slices.Sort(ids)
	}
	return m
}

func requireErrors(t *testing.T, res audit.Result, want map[audit.ErrorCode][]string) {
	t.Helper()
	if res.Valid {
		t.Fatalf("expected an invalid result, got valid chain %v", res.Chain)
	}
	if got := errIndex(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected errors:\n got: %v\nwant: %v", got, want)
	}
}

func TestAuditAcceptsValidChainRegardlessOfOrder(t *testing.T) {
	chain := buildChain(t, 64)
	wantOrder := make([]string, 0, len(chain))
	for _, e := range chain {
		wantOrder = append(wantOrder, e.ID)
	}

	for seed := uint64(1); seed <= 25; seed++ {
		res := audit.Audit(shuffle(chain, seed))
		if !res.Valid {
			t.Fatalf("seed %d: expected valid chain, got errors %v", seed, res.Errors)
		}
		if !slices.Equal(res.Chain, wantOrder) {
			t.Fatalf("seed %d: chain order mismatch:\n got: %v\nwant: %v", seed, res.Chain, wantOrder)
		}
		if res.TailDigest != chain[len(chain)-1].Digest {
			t.Fatalf("seed %d: tail digest = %s, want %s", seed, res.TailDigest, chain[len(chain)-1].Digest)
		}
		if res.EventCount != len(chain) {
			t.Fatalf("seed %d: event count = %d, want %d", seed, res.EventCount, len(chain))
		}
	}
}

func TestAuditAcceptsSingleRootEvent(t *testing.T) {
	chain := buildChain(t, 1)
	res := audit.Audit(chain)
	if !res.Valid || len(res.Chain) != 1 || res.Chain[0] != "ev-000" || res.TailDigest != chain[0].Digest {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// A payload altered after sealing invalidates only the tampered event's own
// digest; the linkage of its successor still matches the declared digest.
func TestAuditDetectsPayloadTamper(t *testing.T) {
	chain := buildChain(t, 8)
	chain[4].Payload = "sealed evidence bag 4 (contents swapped)"

	res := audit.Audit(shuffle(chain, 7))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeDigestMismatch: {"ev-004"},
	})
}

// A declared digest altered after sealing is caught by recomputation.
func TestAuditDetectsDigestTamper(t *testing.T) {
	chain := buildChain(t, 5)
	d := chain[4].Digest
	if d[63] == 'a' {
		d = d[:63] + "b"
	} else {
		d = d[:63] + "a"
	}
	chain[4].Digest = d

	res := audit.Audit(shuffle(chain, 8))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeDigestMismatch: {"ev-004"},
	})
}

// A parent reference pointing at a non-existent event breaks the chain
// without touching any digest: the tampered event still recomputes cleanly.
func TestAuditDetectsDanglingParentReference(t *testing.T) {
	chain := buildChain(t, 8)
	chain[5].ParentID = "ev-999" // does not exist

	res := audit.Audit(shuffle(chain, 9))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeMissingParent: {"ev-005"},
	})
}

// A parent reference re-pointed at another existing event both forks that
// event and breaks the prevDigest linkage of the re-pointed one.
func TestAuditDetectsRepointedParentReference(t *testing.T) {
	chain := buildChain(t, 8)
	chain[5].ParentID = "ev-001" // exists, but is not the true predecessor

	res := audit.Audit(shuffle(chain, 10))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeFork:               {"ev-001"},
		audit.CodePrevDigestMismatch: {"ev-005"},
	})
}

// A second event sealed on top of the same predecessor, with internally
// consistent digests, is reported purely as a fork.
func TestAuditDetectsFork(t *testing.T) {
	chain := buildChain(t, 8)
	extra := audit.Event{
		ID:         "ev-003-bis",
		ParentID:   "ev-003",
		Payload:    "conflicting seal record",
		PrevDigest: chain[3].Digest,
	}
	extra.Digest = mustDigest(t, extra.ID, extra.PrevDigest, extra.Payload)

	res := audit.Audit(shuffle(append(slices.Clone(chain), extra), 11))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeFork: {"ev-003"},
	})
	for _, e := range res.Errors {
		if !strings.Contains(e.Message, "ev-004") || !strings.Contains(e.Message, "ev-003-bis") {
			t.Fatalf("fork error should name both children, got %q", e.Message)
		}
	}
}

func TestAuditDetectsCycle(t *testing.T) {
	chain := buildChain(t, 4)
	chain[1].ParentID = "ev-003" // ev-001 -> ev-003 -> ev-002 -> ev-001

	res := audit.Audit(shuffle(chain, 12))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeCycle:              {"ev-001", "ev-002", "ev-003"},
		audit.CodePrevDigestMismatch: {"ev-001"},
	})
}

func TestAuditDetectsMissingRoot(t *testing.T) {
	chain := buildChain(t, 4)
	chain[0].ParentID = "ev-ghost"

	res := audit.Audit(shuffle(chain, 13))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeMissingParent: {"ev-000"},
		audit.CodeNoRoot:        {""},
	})
}

func TestAuditDetectsMultipleRoots(t *testing.T) {
	chain := buildChain(t, 4)
	other := audit.Event{ID: "ev-other-root", Payload: "second root", PrevDigest: audit.ZeroDigest}
	other.Digest = mustDigest(t, other.ID, other.PrevDigest, other.Payload)

	res := audit.Audit(shuffle(append(slices.Clone(chain), other), 14))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeMultipleRoots: {"ev-000", "ev-other-root"},
	})
}

// A prevDigest overwritten and re-sealed (digest recomputed to match) breaks
// only the linkage to the true predecessor.
func TestAuditDetectsPrevDigestTamper(t *testing.T) {
	chain := buildChain(t, 6)
	chain[5].PrevDigest = strings.Repeat("ab", 32)
	chain[5].Digest = mustDigest(t, chain[5].ID, chain[5].PrevDigest, chain[5].Payload)

	res := audit.Audit(shuffle(chain, 15))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodePrevDigestMismatch: {"ev-005"},
	})
}

// A root sealed with a non-zero prevDigest is a linkage anomaly even when
// the rest of the chain is recomputed consistently on top of it.
func TestAuditDetectsNonZeroRootPrevDigest(t *testing.T) {
	chain := buildChainFrom(t, 4, strings.Repeat("cd", 32))

	res := audit.Audit(shuffle(chain, 16))
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodePrevDigestMismatch: {"ev-000"},
	})
}

func TestAuditRejectsDuplicateIDs(t *testing.T) {
	chain := buildChain(t, 3)
	events := append(slices.Clone(chain), chain[2])

	res := audit.Audit(events)
	requireErrors(t, res, map[audit.ErrorCode][]string{
		audit.CodeDuplicateID: {"ev-002"},
	})
}

// The same corrupted set must yield byte-identical, sorted findings no
// matter how the upload order is shuffled.
func TestAuditFindingsAreDeterministicAcrossShuffles(t *testing.T) {
	chain := buildChain(t, 10)
	chain[3].Payload = "tampered payload" // DIGEST_MISMATCH(ev-003)
	chain[7].ParentID = "ev-003"          // FORK(ev-003) + PREV_DIGEST_MISMATCH(ev-007)

	base := audit.Audit(shuffle(chain, 100))
	if base.Valid {
		t.Fatal("expected an invalid result")
	}
	if !slices.IsSortedFunc(base.Errors, func(a, b audit.AuditError) int {
		if c := strings.Compare(string(a.Code), string(b.Code)); c != 0 {
			return c
		}
		return strings.Compare(a.EventID, b.EventID)
	}) {
		t.Fatalf("errors are not sorted by (code, eventId): %v", base.Errors)
	}

	for seed := uint64(101); seed < 120; seed++ {
		res := audit.Audit(shuffle(chain, seed))
		if !reflect.DeepEqual(res.Errors, base.Errors) {
			t.Fatalf("seed %d: findings differ across shuffles:\n got: %v\nwant: %v", seed, res.Errors, base.Errors)
		}
	}
}
