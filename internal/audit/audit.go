package audit

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Audit verifies a set of evidence-seal events as an unordered collection:
// the outcome never depends on the order events appear in the input.
//
// It checks, over the whole set: exactly one root (empty ParentID), every
// parent reference resolves, no parent-reference cycles, at most one child
// per predecessor, every prevDigest equals the predecessor's declared digest
// (all zeros for the root), and every declared digest recomputes correctly.
//
// All anomalies are returned sorted by (code, eventId). Only when no anomaly
// exists — which implies the events form one complete chain — does the
// result carry the root-to-tail sequence and the tail digest.
func Audit(events []Event) Result {
	byID := make(map[string]Event, len(events))
	var dupes []string
	for _, e := range events {
		if _, seen := byID[e.ID]; seen {
			dupes = append(dupes, e.ID)
			continue
		}
		byID[e.ID] = e
	}
	if len(dupes) > 0 {
		slices.Sort(dupes)
		errs := make([]AuditError, 0, len(dupes))
		for _, id := range dupes {
			errs = append(errs, AuditError{
				Code:    CodeDuplicateID,
				EventID: id,
				Message: fmt.Sprintf("event id %q appears more than once", id),
			})
		}
		return Result{Valid: false, EventCount: len(events), Errors: errs}
	}

	var errs []AuditError

	// Roots, parent existence and the parent -> children index.
	var roots []string
	children := make(map[string][]string, len(events))
	for _, e := range events {
		if e.ParentID == "" {
			roots = append(roots, e.ID)
			continue
		}
		if _, ok := byID[e.ParentID]; !ok {
			errs = append(errs, AuditError{
				Code:    CodeMissingParent,
				EventID: e.ID,
				Message: fmt.Sprintf("parent event %q is not present in the request", e.ParentID),
			})
			continue
		}
		children[e.ParentID] = append(children[e.ParentID], e.ID)
	}
	slices.Sort(roots)
	switch {
	case len(roots) == 0:
		errs = append(errs, AuditError{
			Code:    CodeNoRoot,
			Message: "no root event (empty parentId) present; exactly one is required",
		})
	case len(roots) > 1:
		for _, id := range roots {
			errs = append(errs, AuditError{
				Code:    CodeMultipleRoots,
				EventID: id,
				Message: fmt.Sprintf("expected exactly one root event, found %d", len(roots)),
			})
		}
	}

	// Forks: a predecessor with more than one child.
	var forkParents []string
	for parent, kids := range children {
		if len(kids) > 1 {
			forkParents = append(forkParents, parent)
		}
	}
	slices.Sort(forkParents)
	for _, parent := range forkParents {
		kids := children[parent]
		slices.Sort(kids)
		errs = append(errs, AuditError{
			Code:    CodeFork,
			EventID: parent,
			Message: fmt.Sprintf("event %q has %d children (%s); each predecessor may have at most one", parent, len(kids), strings.Join(kids, ", ")),
		})
	}

	// Cycles in the parent-reference graph.
	for _, id := range cycleMembers(events, byID) {
		errs = append(errs, AuditError{
			Code:    CodeCycle,
			EventID: id,
			Message: fmt.Sprintf("event %q is part of a parent-reference cycle", id),
		})
	}

	// Digest integrity of every individual event.
	for _, e := range events {
		if !IsDigestFormat(e.PrevDigest) || !IsDigestFormat(e.Digest) {
			errs = append(errs, AuditError{
				Code:    CodeInvalidDigestFormat,
				EventID: e.ID,
				Message: "prevDigest and digest must be 64 lowercase hexadecimal characters",
			})
			continue
		}
		if e.ParentID == "" {
			if e.PrevDigest != ZeroDigest {
				errs = append(errs, AuditError{
					Code:    CodePrevDigestMismatch,
					EventID: e.ID,
					Message: "root event prevDigest must be all zeros",
				})
			}
		} else if parent, ok := byID[e.ParentID]; ok && e.PrevDigest != parent.Digest {
			errs = append(errs, AuditError{
				Code:    CodePrevDigestMismatch,
				EventID: e.ID,
				Message: fmt.Sprintf("prevDigest does not match the declared digest of parent %q", e.ParentID),
			})
		}
		prevRaw, _ := hex.DecodeString(e.PrevDigest) // format checked above
		if got := ComputeDigestWithRawPrev(e.ID, prevRaw, e.Payload); got != e.Digest {
			errs = append(errs, AuditError{
				Code:    CodeDigestMismatch,
				EventID: e.ID,
				Message: "declared digest does not match the digest recomputed from id, prevDigest and payload",
			})
		}
	}

	slices.SortFunc(errs, func(a, b AuditError) int {
		return cmp.Or(cmp.Compare(a.Code, b.Code), cmp.Compare(a.EventID, b.EventID))
	})

	if len(errs) > 0 {
		return Result{Valid: false, EventCount: len(events), Errors: errs}
	}

	// No anomalies: exactly one root, every parent exists, no cycles and no
	// forks, so the events necessarily form a single chain covering all of
	// them. Walk it from the root to the tail.
	chain := make([]string, 0, len(events))
	for cur := roots[0]; cur != ""; {
		chain = append(chain, cur)
		kids := children[cur]
		if len(kids) == 0 {
			break
		}
		cur = kids[0] // fork-free: at most one child
	}
	return Result{
		Valid:      true,
		EventCount: len(events),
		Chain:      chain,
		TailDigest: byID[chain[len(chain)-1]].Digest,
	}
}

// cycleMembers returns the sorted ids of all events that sit on a cycle of
// parent references. Every event has at most one parent, so following
// parent pointers from any unvisited event either terminates (root, missing
// parent, or an already resolved event) or closes a cycle.
func cycleMembers(events []Event, byID map[string]Event) []string {
	const (
		unvisited = iota
		inPath
		done
	)
	state := make(map[string]int, len(events))
	inCycle := make(map[string]bool)

	for _, e := range events {
		if state[e.ID] != unvisited {
			continue
		}
		var path []string
		cur := e.ID
	walk:
		for cur != "" {
			switch state[cur] {
			case done:
				break walk
			case inPath:
				// cur re-enters the current path: everything from its
				// first occurrence onward forms the cycle.
				for i, id := range path {
					if id == cur {
						for _, member := range path[i:] {
							inCycle[member] = true
						}
						break
					}
				}
				break walk
			}
			state[cur] = inPath
			path = append(path, cur)
			parent := byID[cur].ParentID
			if parent != "" {
				if _, ok := byID[parent]; !ok {
					break walk // missing parent: reported separately
				}
			}
			cur = parent
		}
		for _, id := range path {
			state[id] = done
		}
	}

	members := make([]string, 0, len(inCycle))
	for id := range inCycle {
		members = append(members, id)
	}
	slices.Sort(members)
	return members
}
