package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// ZeroDigest is the all-zero digest used as prevDigest of the root event.
const ZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// IsDigestFormat reports whether s is exactly 64 lowercase hexadecimal
// characters, the canonical form of a SHA-256 digest in this API.
func IsDigestFormat(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ComputeDigest derives the digest of an event from its canonical fields:
//
//	SHA-256( BE32(len(id)) || id || prevDigest(32 raw bytes) ||
//	         BE32(len(payload)) || payload )
//
// where lengths are 4-byte big-endian and id/payload are UTF-8 bytes.
func ComputeDigest(id, prevDigestHex, payload string) (string, error) {
	prev, err := hex.DecodeString(prevDigestHex)
	if err != nil || len(prev) != sha256.Size {
		return "", fmt.Errorf("prevDigest must be 64 hexadecimal characters decoding to 32 bytes")
	}
	return ComputeDigestWithRawPrev(id, prev, payload), nil
}

// ComputeDigestWithRawPrev is ComputeDigest with the previous digest already
// decoded. prevDigestRaw must be exactly 32 bytes.
func ComputeDigestWithRawPrev(id string, prevDigestRaw []byte, payload string) string {
	h := sha256.New()
	var lenBuf [4]byte

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(id)))
	h.Write(lenBuf[:])
	h.Write([]byte(id))

	h.Write(prevDigestRaw)

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	h.Write(lenBuf[:])
	h.Write([]byte(payload))

	return hex.EncodeToString(h.Sum(nil))
}
