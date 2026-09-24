// chaingen generates a valid evidence-seal chain as a JSON document ready to
// POST to /audit. It exists so auditors can produce known-good chains and
// then corrupt them by hand to exercise the API.
//
// Usage: go run ./cmd/chaingen -n 3 | curl -s -X POST --data @- localhost:8080/audit
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"evidence-audit/internal/audit"
)

func main() {
	n := flag.Int("n", 3, "number of events to generate (>= 1)")
	flag.Parse()
	if *n < 1 {
		log.Fatal("n must be >= 1")
	}

	events := make([]audit.Event, 0, *n)
	prev, parent := audit.ZeroDigest, ""
	for i := 0; i < *n; i++ {
		id := fmt.Sprintf("ev-%03d", i)
		payload := fmt.Sprintf("evidence seal record %d", i)
		digest, err := audit.ComputeDigest(id, prev, payload)
		if err != nil {
			log.Fatal(err)
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

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"events": events}); err != nil {
		log.Fatal(err)
	}
}
