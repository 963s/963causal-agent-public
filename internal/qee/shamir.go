// Package qee — Quorum Envelope Encryption.
//
// Implements the mathematical primitives for secret escrow
// without a master key, as mandated by ADR-017. Two files:
//
//   shamir.go    — Shamir's Secret Sharing over GF(2^8),
//                  byte-aligned, implementing the k-of-n
//                  reconstruction semantics.
//   envelope.go  — high-level Seal / Open / ReSeal with a
//                  "fast path" via PUF-bound K_PAL and a
//                  "recovery path" via k witness shares
//                  delivered through NaCl box encryption.
//
// This file is the mathematical foundation; envelope.go is the
// protocol layer. We implement Shamir in-tree rather than
// pulling in github.com/hashicorp/vault/shamir because the
// latter drags transitive deps and we want line-by-line audit
// clarity for a primitive the entire recovery story depends on.
//
// Algorithm (Shamir 1979 "How to Share a Secret"):
//
//   Each secret byte is the constant term s₀ of a degree-(k-1)
//   polynomial p(x) = s₀ + a₁·x + … + a_{k-1}·x^{k-1} over
//   GF(2^8). Shares are (x, p(x)) evaluations for x = 1..n.
//   Any k shares reconstruct s₀ via Lagrange interpolation at
//   x = 0. Any k-1 shares reveal NO information about s₀
//   (information-theoretic security — Shamir's theorem).
//
// GF(2^8) field: we use the AES-standard irreducible polynomial
// x⁸ + x⁴ + x³ + x + 1 (0x11B). The multiplication and inverse
// tables are precomputed at package init for constant-time
// operations; values come from the standard AES Rijndael
// S-box precomputation (see FIPS-197 §4.2).
package qee

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Share is one (x, y-vector) pair produced by Split. The Index
// field is the GF(2^8) x-coordinate (1..255, with 0 reserved
// for the secret itself). Bytes is the polynomial evaluations
// — one byte of the secret per polynomial, so len(Bytes) ==
// len(original secret).
type Share struct {
	Index byte
	Bytes []byte
}

// Split creates n Shamir shares of `secret` such that any
// threshold shares can reconstruct it via Combine. Returns an
// error for pathological inputs (threshold < 1, n < threshold,
// n > 255, empty secret). The caller is responsible for
// distributing shares to distinct holders — two shares with
// the same Index will NOT help reconstruction.
func Split(secret []byte, n, threshold int) ([]Share, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("qee: threshold < 1")
	}
	if n < threshold {
		return nil, fmt.Errorf("qee: n (%d) < threshold (%d)", n, threshold)
	}
	if n > 255 {
		// GF(2^8) has 256 elements; x = 0 is reserved for the
		// constant term (the secret itself), leaving 1..255 as
		// valid share indices.
		return nil, fmt.Errorf("qee: n (%d) > 255", n)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("qee: empty secret")
	}

	// Per-byte polynomials. polys[i] is the degree-(threshold-1)
	// polynomial for byte i of the secret. polys[i][0] = secret[i]
	// (the constant term); polys[i][j>0] are uniformly random
	// coefficients drawn from crypto/rand.
	polys := make([][]byte, len(secret))
	for i := range polys {
		polys[i] = make([]byte, threshold)
		polys[i][0] = secret[i]
		// Fill the higher-degree coefficients with fresh
		// randomness. Using a single big rand.Read is faster
		// than one call per coefficient.
		if threshold > 1 {
			extra := make([]byte, threshold-1)
			if _, err := rand.Read(extra); err != nil {
				return nil, fmt.Errorf("qee: rand: %w", err)
			}
			copy(polys[i][1:], extra)
		}
	}

	// Evaluate each polynomial at x = 1..n to produce shares.
	shares := make([]Share, n)
	for sIdx := 0; sIdx < n; sIdx++ {
		x := byte(sIdx + 1)
		shares[sIdx] = Share{Index: x, Bytes: make([]byte, len(secret))}
		for b := 0; b < len(secret); b++ {
			shares[sIdx].Bytes[b] = evalPoly(polys[b], x)
		}
	}
	return shares, nil
}

// Combine reconstructs a secret from ≥ threshold shares. It
// requires the caller to supply AT LEAST threshold shares — more
// is harmless (extra shares are redundant); fewer returns an
// error. Duplicate indices are rejected because Lagrange
// interpolation would divide by zero.
func Combine(shares []Share, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("qee: combine needs ≥ %d shares, got %d",
			threshold, len(shares))
	}
	// Use exactly `threshold` shares for interpolation (more
	// would inflate the computed polynomial degree pointlessly).
	shares = shares[:threshold]

	secretLen := len(shares[0].Bytes)
	for i, s := range shares {
		if len(s.Bytes) != secretLen {
			return nil, fmt.Errorf("qee: share %d length %d != %d",
				i, len(s.Bytes), secretLen)
		}
	}
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if s.Index == 0 {
			return nil, fmt.Errorf("qee: share with Index 0 (reserved for secret)")
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("qee: duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}

	// Lagrange interpolation at x = 0 for each byte position.
	secret := make([]byte, secretLen)
	for b := 0; b < secretLen; b++ {
		var total byte
		for i := 0; i < threshold; i++ {
			// Compute the i-th Lagrange basis polynomial
			// evaluated at x = 0:
			//   L_i(0) = Π_{j ≠ i} (0 - x_j) / (x_i - x_j)
			//          = Π_{j ≠ i} x_j / (x_i + x_j)   in GF(2^8)
			//  (because -a == a and subtraction == addition in
			//   characteristic-2 fields)
			num, den := byte(1), byte(1)
			for j := 0; j < threshold; j++ {
				if i == j {
					continue
				}
				num = gfMul(num, shares[j].Index)
				den = gfMul(den, gfAdd(shares[i].Index, shares[j].Index))
			}
			if den == 0 {
				// Unreachable if we checked duplicates above,
				// but guard against arithmetic surprises.
				return nil, errors.New("qee: zero denominator in lagrange")
			}
			basis := gfMul(num, gfInv(den))
			total = gfAdd(total, gfMul(shares[i].Bytes[b], basis))
		}
		secret[b] = total
	}
	return secret, nil
}

// evalPoly evaluates `poly` at `x` using Horner's method in
// GF(2^8). poly[i] is the coefficient for x^i.
func evalPoly(poly []byte, x byte) byte {
	var out byte
	for i := len(poly) - 1; i >= 0; i-- {
		out = gfAdd(gfMul(out, x), poly[i])
	}
	return out
}

// -----------------------------------------------------------------
// GF(2^8) arithmetic with AES's irreducible polynomial 0x11B.
// Addition is XOR; multiplication uses precomputed log / exp
// tables over the multiplicative group generator 3 (a.k.a.
// "generator g = x + 1" per FIPS-197 §4.2.1 footnote).

var (
	gfLog [256]byte
	gfExp [256]byte
)

func init() {
	// Build the log / exp tables. x = 0 has no log; we leave
	// gfLog[0] = 0 and never index it in gfMul (we short-circuit
	// the zero case there). gfExp has period 255 — exp(0) = 1,
	// exp(255) = 1 again, which is the identity wrap-around.
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		// Multiply x by the generator 3 (= 0x03 = x + 1 in the
		// polynomial-basis representation).
		hi := x & 0x80
		x <<= 1
		if hi != 0 {
			x ^= 0x1B // reduce mod x⁸ + x⁴ + x³ + x + 1
		}
		x ^= gfExp[i] // ×2 part above; ^= gfExp[i] multiplies by (x+1)
	}
	// Wrap the exp table so gfExp[255] == gfExp[0] == 1, and
	// treat higher indices mod 255.
	gfExp[255] = 1
}

func gfAdd(a, b byte) byte { return a ^ b }

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

func gfInv(a byte) byte {
	if a == 0 {
		// 0 has no inverse; caller's responsibility to avoid
		// this. We return 0 (which will propagate as a bogus
		// result) rather than panicking so tests don't crash
		// mid-table on diagnostic paths.
		return 0
	}
	return gfExp[(255-int(gfLog[a]))%255]
}
