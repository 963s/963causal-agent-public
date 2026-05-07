package qee

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestShamirRoundTrip covers the basic (3-of-5) round trip with
// a varied-length secret. Having secretLen ≠ threshold tests
// that each byte is processed independently; having n > threshold
// tests that extra shares are tolerated in Combine.
func TestShamirRoundTrip(t *testing.T) {
	secret := []byte("the quick brown fox jumps over the lazy dog")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("want 5 shares, got %d", len(shares))
	}
	// Try each 3-subset; they should all reconstruct.
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 4; j++ {
			for k := j + 1; k < 5; k++ {
				got, err := Combine([]Share{shares[i], shares[j], shares[k]}, 3)
				if err != nil {
					t.Fatalf("combine {%d,%d,%d}: %v", i, j, k, err)
				}
				if !bytes.Equal(got, secret) {
					t.Fatalf("combine {%d,%d,%d}: got %q want %q", i, j, k, got, secret)
				}
			}
		}
	}
}

// TestShamirBelowThresholdReveals confirms k-1 shares are NOT
// enough to reconstruct. This is the core Shamir security
// property; failing here would indicate a fatal bug (the
// reconstructed value would leak bits of the secret).
func TestShamirBelowThresholdReveals(t *testing.T) {
	secret := []byte("a very sensitive secret")
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	// Try with only 2 shares — Combine should error out because
	// we demanded threshold = 3.
	if _, err := Combine(shares[:2], 3); err == nil {
		t.Fatal("combine with 2 shares unexpectedly succeeded (need 3)")
	}
	// A different attack: call Combine with threshold=2 and 2
	// shares. It will succeed structurally but will NOT produce
	// the right secret because the polynomial was degree-2.
	// We test that the output is different from `secret`.
	wrongRecon, err := Combine(shares[:2], 2)
	if err != nil {
		t.Fatalf("combine threshold=2: %v", err)
	}
	if bytes.Equal(wrongRecon, secret) {
		t.Fatal("wrong-threshold combine happened to match the secret (astronomical; check impl)")
	}
}

// TestShamirDuplicateIndexRejected catches the Lagrange-
// degenerate case where two shares share an x-coordinate.
func TestShamirDuplicateIndexRejected(t *testing.T) {
	secret := []byte("test")
	shares, _ := Split(secret, 5, 3)
	shares[1].Index = shares[0].Index
	if _, err := Combine(shares[:3], 3); err == nil {
		t.Fatal("combine accepted duplicate indexes")
	}
}

// TestShamirLargeSecret exercises the implementation on a
// 4 KiB random secret to confirm per-byte correctness scales.
func TestShamirLargeSecret(t *testing.T) {
	secret := make([]byte, 4096)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}
	shares, err := Split(secret, 7, 4)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	recon, err := Combine([]Share{shares[0], shares[2], shares[4], shares[6]}, 4)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(recon, secret) {
		t.Fatalf("large-secret round trip: mismatch at %d bytes", diffOffset(recon, secret))
	}
}

// TestShamirGFArithmetic is a narrow regression for the GF(2^8)
// tables: multiply every non-zero pair through gfMul and check
// against a simple polynomial-basis reference.
func TestShamirGFArithmetic(t *testing.T) {
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			got := gfMul(byte(a), byte(b))
			want := gfMulReference(byte(a), byte(b))
			if got != want {
				t.Fatalf("gfMul(%#x, %#x) = %#x; want %#x", a, b, got, want)
			}
		}
	}
	// inverse: a · a⁻¹ must be 1 for all non-zero a.
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("gfInv(%#x) fails identity check", a)
		}
	}
}

// gfMulReference is a slow but transparent polynomial-basis
// multiplication in GF(2^8) mod 0x11B. Used exclusively by
// TestShamirGFArithmetic to cross-check the table-based gfMul.
func gfMulReference(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

func diffOffset(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
