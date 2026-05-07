package puf

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Verdict is the server-side classification of a PUF attestation result
// relative to its enrolled baseline. Thresholds are tuneable and live in
// the control plane, not in the agent, so operators can adjust without
// redeploying fleet agents.
type Verdict string

const (
	VerdictPass   Verdict = "PASS"   // measurement within stable window
	VerdictDrift  Verdict = "DRIFT"  // measurement noisy but not catastrophic
	VerdictTamper Verdict = "TAMPER" // measurement implies different silicon
	VerdictError  Verdict = "ERROR"  // inputs could not be compared
)

// DefaultPassRatio is the Hamming-distance ratio below which an attestation
// is considered a pass. Derived from an expected bit-error rate of ~5% per
// position and a 3-sigma noise envelope. Expected to be refined after real
// fleet data is collected in W5a.
const DefaultPassRatio = 0.15

// DefaultDriftRatio is the ratio above which we escalate from DRIFT to
// TAMPER. Between pass and drift the attestation is still recorded as a
// warning but does not lock the host.
const DefaultDriftRatio = 0.30

// HammingDistance returns the number of differing bits between a and b.
// Both slices must carry the same bit length; an error is returned
// otherwise rather than silently truncating. The length is measured in
// bits, not bytes, because our fingerprints are typically not a multiple
// of eight bits long and the trailing padding must be ignored.
func HammingDistance(a, b []byte, length int) (int, error) {
	if length < 0 {
		return 0, fmt.Errorf("puf: negative length %d", length)
	}
	if length == 0 {
		return 0, nil
	}
	needed := (length + 7) >> 3
	if len(a) < needed || len(b) < needed {
		return 0, fmt.Errorf("puf: input too short for length %d (a=%d,b=%d bytes)", length, len(a), len(b))
	}
	full := length >> 3
	dist := 0
	for i := 0; i < full; i++ {
		dist += popcount(a[i] ^ b[i])
	}
	rem := uint(length & 7)
	if rem > 0 {
		mask := byte((1 << rem) - 1)
		dist += popcount((a[full] ^ b[full]) & mask)
	}
	return dist, nil
}

// popcount returns the number of set bits in a byte. 8-bit table lookup
// because Go does not expose the architecture-specific popcount intrinsic
// directly; the table is built at init time so the routine is branch-free
// in the hot path.
var popcountTable [256]uint8

func init() {
	for i := range popcountTable {
		x := i
		x = (x & 0x55) + ((x >> 1) & 0x55)
		x = (x & 0x33) + ((x >> 2) & 0x33)
		x = (x & 0x0f) + ((x >> 4) & 0x0f)
		popcountTable[i] = uint8(x)
	}
}

func popcount(b byte) int { return int(popcountTable[b]) }

// Compare classifies an attestation fingerprint against an enrolled one
// using the package defaults. Callers that need bespoke thresholds should
// call CompareWith directly.
func Compare(enrolled, attested Fingerprint) (Verdict, int, float64, error) {
	return CompareWith(enrolled, attested, DefaultPassRatio, DefaultDriftRatio)
}

// CompareWith classifies an attestation fingerprint against an enrolled one
// using caller-supplied thresholds. It returns the verdict, raw Hamming
// distance, and the ratio (distance / length) for logging.
//
// Enrolled and attested must carry matching geometry (same number of cores,
// loops, trials and bit length). A mismatch returns VerdictError and never
// silently compares apples to oranges — that would hide legitimate tamper
// signals where an attacker reduced the core count to mask a VM clone.
func CompareWith(enrolled, attested Fingerprint, passRatio, driftRatio float64) (Verdict, int, float64, error) {
	if enrolled.Length == 0 || attested.Length == 0 {
		return VerdictError, 0, 0, fmt.Errorf("puf: empty fingerprint")
	}
	if enrolled.Length != attested.Length {
		return VerdictError, 0, 0, fmt.Errorf("puf: length mismatch (enrolled=%d, attested=%d)",
			enrolled.Length, attested.Length)
	}
	if enrolled.Cores != attested.Cores || enrolled.Loops != attested.Loops {
		return VerdictError, 0, 0, fmt.Errorf("puf: geometry mismatch (enrolled=%dc/%dl, attested=%dc/%dl)",
			enrolled.Cores, enrolled.Loops, attested.Cores, attested.Loops)
	}

	dist, err := HammingDistance(enrolled.Bits, attested.Bits, enrolled.Length)
	if err != nil {
		return VerdictError, 0, 0, err
	}
	ratio := float64(dist) / float64(enrolled.Length)

	switch {
	case ratio <= passRatio:
		return VerdictPass, dist, ratio, nil
	case ratio <= driftRatio:
		return VerdictDrift, dist, ratio, nil
	default:
		return VerdictTamper, dist, ratio, nil
	}
}

// DigestHex recomputes the SHA3-256 digest of a raw bit-packed fingerprint.
// Exported so the control plane can verify that a submitted Fingerprint
// struct has not been torn apart in transit.
func DigestHex(bits []byte, length int) string {
	h := sha3.New256()
	h.Write(bits)
	h.Write([]byte{byte(length)})
	return hex.EncodeToString(h.Sum(nil))
}
