package puf

import (
	"encoding/hex"
	"math"
	"time"

	"golang.org/x/crypto/sha3"
)

// QuantizeV3 is the second redesign attempt for W5b. V2 measured 41
// stable bits / 192 candidates on a 4-core Ampere Altra cloud VM
// (cmd/puf-ber, 50 cycles, 2026-04-17), with all 36 ratio-gray bits
// and 5 residual-gray bits passing the BER ≤ 2% bar. The V1 sources
// (pair-sign, per-core-vs-med, CV-quartile, pair-magnitude) and the
// new sub-window source contributed zero reliable bits because they
// all compare quantities that are too close on cloud-grade
// homogenised silicon.
//
// V3 keeps only the sources that actually yielded entropy and adds
// three new ones, each chosen because it bins quantities that are
// either large-and-spread (silicon-stable) or measure intrinsic per-
// cell properties (no cross-core comparison needed):
//
//   1. residual-gray V3 (3 bits/cell × 12 cells = 36)
//        — same construction as V2 but with wider buckets at ±0.5σ,
//          ±2σ, ±5σ. Most current measurements land in the centre
//          three buckets even under load, so the gray code is
//          near-deterministic for healthy hosts.
//
//   2. cross-loop ratio-gray (3 bits per (core, loop-pair) × 4 cores
//      × 3 loop-pairs = 36)
//        — verbatim from V2; this is the "gold" group (all 36 stable).
//
//   3. cross-core ratio-gray (3 bits per (loop, core-pair) × 3 loops
//      × C(4,2) = 6 pairs = 54)
//        — same idea but across cores instead of loops. Buckets
//          are tighter (0.97..1.03) because cross-core ratios on
//          matched cores cluster near 1.0.
//
//   4. magnitude-gray (3 bits/cell × 12 cells = 36)
//        — log2(median) bucketed at integer + half-integer steps.
//          The integer portion is the silicon's clock × IPC ceiling
//          and is rock-stable; the fractional portion drifts a bit
//          but the gray code keeps the drift to a single bit flip.
//
//   5. cv-magnitude-gray (3 bits/cell × 12 cells = 36)
//        — coefficient of variation bucketed at log scale. CV is a
//          per-core noise signature that depends on the silicon's
//          power-delivery and thermal coupling rather than its
//          neighbours, so cross-core jitter doesn't affect it.
//
// Total: 36 + 36 + 54 + 36 + 36 = 198 candidate bits. Goal: ≥80
// reliable bits at BER ≤ 2%, enough for a single BCH(127, 64, 10)
// block carrying a 64-bit secret. (128-bit security requires two
// blocks → 254 PUF bits; if V3 falls short we'll add more loop kinds
// in V4 rather than chase noise on this 4-core SKU.)
func QuantizeV3(m Matrix, baseline *Baseline) Fingerprint {
	medians := make([][]float64, m.NumCores)
	cvs := make([][]float64, m.NumCores)
	for c := 0; c < m.NumCores; c++ {
		medians[c] = make([]float64, m.NumLoops)
		cvs[c] = make([]float64, m.NumLoops)
		for l := 0; l < m.NumLoops; l++ {
			rs := make([]float64, m.NumTrials)
			for t := 0; t < m.NumTrials; t++ {
				rs[t] = m.Samples[c][l][t].ItersPerSec()
			}
			med, _ := medianMAD(rs)
			medians[c][l] = med
			cvs[c][l] = cvOf(rs)
		}
	}

	var bits bitBuilder

	// (1) residual-gray V3 — wider buckets than V2.
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			level := residualBucketWide(medians[c][l], baseline, c, l)
			emitGray3(&bits, level)
		}
	}

	// (2) cross-loop ratio-gray — generalised to any loop count. With
	// L loops we emit C(L, 2) ratios per core. V3 ran with L=3 and 3
	// pairs; V4 runs with L=5 and 10 pairs. The for-loop walks pairs
	// in (la, lb) ascending order so the bit positions are
	// reproducible across enrolments that use the same L.
	for la := 0; la < m.NumLoops; la++ {
		for lb := la + 1; lb < m.NumLoops; lb++ {
			for c := 0; c < m.NumCores; c++ {
				ratio := safeRatio(medians[c][la], medians[c][lb])
				emitGray3(&bits, ratioBucket(ratio))
			}
		}
	}

	// (3) cross-core ratio-gray — within each loop, gray-code the
	// pairwise core ratio with tight buckets centred on 1.0. We
	// always divide larger / smaller so the ratio is ≥ 1, which
	// halves the bucket-domain we have to cover.
	for l := 0; l < m.NumLoops; l++ {
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				x, y := medians[a][l], medians[b][l]
				if y > x {
					x, y = y, x
				}
				ratio := safeRatio(x, y) // ≥ 1
				emitGray3(&bits, crossCoreBucket(ratio))
			}
		}
	}

	// (4) magnitude-gray — log2(median) bucketed.
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			emitGray3(&bits, magnitudeBucket(medians[c][l]))
		}
	}

	// (5) cv-magnitude-gray — log10(CV) bucketed. CV typically lives
	// in the 1e-4..1e-1 range; log10 buckets evenly cover that span.
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			emitGray3(&bits, cvMagnitudeBucket(cvs[c][l]))
		}
	}

	packed := bits.bytes()
	h := sha3.New256()
	h.Write(packed)
	h.Write([]byte{byte(bits.length), 0x03 /* version tag */})
	digest := hex.EncodeToString(h.Sum(nil))

	return Fingerprint{
		Bits:       packed,
		Length:     bits.length,
		Cores:      m.NumCores,
		Loops:      m.NumLoops,
		Trials:     m.NumTrials,
		Digest:     digest,
		MeasuredAt: time.Now().UTC(),
	}
}

// residualBucketWide is the V3 residual quantiser. Buckets are at
// ±0.5σ, ±2σ, ±5σ — wider than V2 so single-trial jitter on stable
// cells stays in the centre bucket and only sustained drift crosses
// a boundary. Returns 4 (centre) when no baseline is supplied.
func residualBucketWide(current float64, baseline *Baseline, core, loop int) uint8 {
	if baseline == nil {
		return 4
	}
	var bMed, bMAD float64
	for _, cs := range baseline.PerCoreLoop {
		if cs.Core == core && int(cs.Loop) == loop {
			bMed = cs.Median
			bMAD = cs.MAD
			break
		}
	}
	if bMed == 0 {
		return 4
	}
	floor := bMed * 0.002
	if bMAD < floor {
		bMAD = floor
	}
	z := (current - bMed) / bMAD
	switch {
	case z <= -5:
		return 0
	case z <= -2:
		return 1
	case z <= -0.5:
		return 2
	case z <= 0:
		return 3
	case z <= 0.5:
		return 4
	case z <= 2:
		return 5
	case z <= 5:
		return 6
	default:
		return 7
	}
}

// crossCoreBucket maps a cross-core ratio (always ≥ 1.0 by
// construction) to one of eight buckets with tight thresholds. Most
// ratios on matched cores will land in bucket 0 or 1 — that is fine,
// the goal is for the *bucket index* to be stable, not for the buckets
// to be evenly populated.
func crossCoreBucket(r float64) uint8 {
	switch {
	case r <= 1.001:
		return 0
	case r <= 1.003:
		return 1
	case r <= 1.007:
		return 2
	case r <= 1.015:
		return 3
	case r <= 1.030:
		return 4
	case r <= 1.060:
		return 5
	case r <= 1.120:
		return 6
	default:
		return 7
	}
}

// magnitudeBucket maps an iterations-per-second value to a log2 bucket.
// Two iter-rate decades cover most micro-benchmark output (~1e7..1e9
// ips on Altra), so we span 24..32 in log2 with half-integer steps.
// Each bucket covers a 1.41× range so cells whose throughput drifts
// by less than that stay put.
func magnitudeBucket(x float64) uint8 {
	if x <= 0 {
		return 0
	}
	l := math.Log2(x)
	switch {
	case l <= 24.0:
		return 0
	case l <= 25.0:
		return 1
	case l <= 26.0:
		return 2
	case l <= 27.0:
		return 3
	case l <= 28.0:
		return 4
	case l <= 29.0:
		return 5
	case l <= 30.0:
		return 6
	default:
		return 7
	}
}

// cvMagnitudeBucket maps a coefficient of variation (typically 1e-4
// .. 1e-1) to a log10 bucket. CV is a noise signature that depends on
// power delivery and thermal coupling — both of which are silicon-
// specific. Eight buckets across three log10 decades give enough
// resolution without straddling the noise floor.
func cvMagnitudeBucket(cv float64) uint8 {
	if cv <= 0 {
		return 0
	}
	l := math.Log10(cv)
	switch {
	case l <= -4.0:
		return 0
	case l <= -3.5:
		return 1
	case l <= -3.0:
		return 2
	case l <= -2.5:
		return 3
	case l <= -2.0:
		return 4
	case l <= -1.5:
		return 5
	case l <= -1.0:
		return 6
	default:
		return 7
	}
}

// emitGray3 appends the three bits of the gray-code representation of
// level (∈ [0, 7]) to bits. Adjacent levels differ in exactly one bit
// position so single-step bucket drift only flips one bit, halving
// the effective bit-error rate compared to a plain binary code.
func emitGray3(bits *bitBuilder, level uint8) {
	gray := level ^ (level >> 1)
	bits.appendBit(gray&1 != 0)
	bits.appendBit(gray&2 != 0)
	bits.appendBit(gray&4 != 0)
}
