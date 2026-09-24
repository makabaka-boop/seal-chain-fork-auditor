package audit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"evidence-audit/internal/audit"
)

// recomputeIndependently rebuilds the event digest byte-by-byte straight
// from the published definition, sharing no code with the implementation:
//
//	BE32(len(id)) || id || prevDigest(32 raw bytes) || BE32(len(payload)) || payload
func recomputeIndependently(t *testing.T, id, prevHex, payload string) string {
	t.Helper()
	prev, err := hex.DecodeString(prevHex)
	if err != nil {
		t.Fatalf("decode prevDigest: %v", err)
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len([]byte(id)))); err != nil {
		t.Fatal(err)
	}
	buf.WriteString(id)
	buf.Write(prev)
	if err := binary.Write(&buf, binary.BigEndian, uint32(len([]byte(payload)))); err != nil {
		t.Fatal(err)
	}
	buf.WriteString(payload)
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func TestComputeDigestMatchesByteForByteDefinition(t *testing.T) {
	cases := []struct{ id, prev, payload string }{
		{"ev-000", audit.ZeroDigest, "evidence bag 1, stored at workstation WS-3"},
		{"证物-α-0001", strings.Repeat("0123456789abcdef", 4), "封签破损，现场重新封装"}, // multibyte UTF-8
		{"x", audit.ZeroDigest, ""}, // empty payload
		{strings.Repeat("長", 100), audit.ZeroDigest, strings.Repeat("証", 200)}, // long multibyte fields
	}
	for _, c := range cases {
		got, err := audit.ComputeDigest(c.id, c.prev, c.payload)
		if err != nil {
			t.Fatalf("ComputeDigest(%q): %v", c.id, err)
		}
		if want := recomputeIndependently(t, c.id, c.prev, c.payload); got != want {
			t.Errorf("ComputeDigest(%q, %q, %q) = %s, want %s", c.id, c.prev, c.payload, got, want)
		}
	}
}

// The golden vector below was produced without any Go code, by feeding the
// manually assembled byte stream to coreutils sha256sum:
//
//	{ printf '\x00\x00\x00\x06ev-000'; head -c 32 /dev/zero; \
//	  printf '\x00\x00\x00\x16evidence seal record 0'; } | sha256sum
func TestComputeDigestGoldenVector(t *testing.T) {
	const want = "971a33f4fd333604d60a7d551290470d242f024378fa18dc0bdb6838f2b0a636"
	got, err := audit.ComputeDigest("ev-000", audit.ZeroDigest, "evidence seal record 0")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("golden vector mismatch: got %s, want %s", got, want)
	}
}

func TestIsDigestFormat(t *testing.T) {
	if !audit.IsDigestFormat(strings.Repeat("a1", 32)) {
		t.Error("64 lowercase hex chars should be accepted")
	}
	if !audit.IsDigestFormat(audit.ZeroDigest) {
		t.Error("all-zero digest should be accepted")
	}
	for name, s := range map[string]string{
		"uppercase":      strings.Repeat("A1", 32),
		"too short":      strings.Repeat("a", 63),
		"too long":       strings.Repeat("a", 65),
		"non hex":        strings.Repeat("g", 64),
		"empty":          "",
		"mixed case":     strings.Repeat("aB", 32),
		"hex with space": " " + strings.Repeat("a", 63),
	} {
		if audit.IsDigestFormat(s) {
			t.Errorf("%s: %q should be rejected", name, s)
		}
	}
}

func TestComputeDigestRejectsMalformedPrevDigest(t *testing.T) {
	for _, prev := range []string{"", "zz", strings.Repeat("a", 62), strings.Repeat("a", 66)} {
		if _, err := audit.ComputeDigest("id", prev, "payload"); err == nil {
			t.Errorf("prevDigest %q: expected an error", prev)
		}
	}
}
