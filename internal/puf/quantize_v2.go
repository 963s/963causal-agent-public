package puf

import (
	"encoding/hex"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

// QuantizeV2 is the W5b candidate quantiser. The W5a Quantize() emits
// 72 bits whose mean BER on a 4-core Ampere Altra cloud VM measured at
// 30% (cmd/puf-ber, 100 cycles, 2026-04-17) — too noisy for any fuzzy
// extractor. V2 widens the candidate pool to ~250 bits drawn from four
// independent entropy sources, and is *designed* to be filtered by a
// downstream reliability-selection pass (SelectReliableBits) that drops
// every bit whose empirical BER over enrolment cycles exceeds a
// chosen ceiling. The remaining bits — the helper-indices set — feed
// the fuzzy extractor.
//
// Sources, in append order:
//
//   1. V1 bits (72)               — kept verbatim so reliability data
//                                   transfers across the V1→V2 cutover.
//   2. baseline-residual gray (3 bits/cell × 12 cells = 36)
//                                  — current cell median normalised by
//                                    baseline MAD, gray-coded across
//                                    eight buckets so single-bucket
//                                    drift flips at most one bit.
//   3. sub-window temporal (4 bits/cell × 12 cells = 48)
//                                  — split each cell's trial sequence
//                                    into 4 windows; each window
//                                    contributes "median(window) >
//                                    cell median". Captures intra-
//                                    cell DVFS slow-loops that are
//                                    silicon-specific.
//   4. cross-loop ratio gray (3 bits per (core, loop-pair) × 4 cores
//      × 3 loop-pairs = 36)
//                                  — for each unordered loop pair
//                                    (int,mem), (int,br), (mem,br),
//                                    encode the per-core ratio as a
//                                    3-bit gray code. The ratio
//                                    integer-int divider relationship
//                                    is set by uarch (issue width,
//                                    cache-port count) and varies
//                                    across silicon revisions.
//
// Total: 72 + 36 + 48 + 36 = 192 candidate bits.
//
// Quantize V2 needs the enrolment baseline to compute (2). The other
// three sources are baseline-free, so V2 also runs at enrolment time
// (where baseline is the cycle being enrolled itself, i.e. residual
// is exactly zero and gray-coded to bucket 4 = 011).
func QuantizeV2(m Matrix, baseline *Baseline) Fingerprint {
	// Per-cell summary: median across trials, MAD across trials, and
	// the raw trial slice (kept for source 3).
	medians := make([][]float64, m.NumCores)
	mads := make([][]float64, m.NumCores)
	trials := make([][][]float64, m.NumCores)
	for c := 0; c < m.NumCores; c++ {
		medians[c] = make([]float64, m.NumLoops)
		mads[c] = make([]float64, m.NumLoops)
		trials[c] = make([][]float64, m.NumLoops)
		for l := 0; l < m.NumLoops; l++ {
			rs := make([]float64, m.NumTrials)
			for t := 0; t < m.NumTrials; t++ {
				rs[t] = m.Samples[c][l][t].ItersPerSec()
			}
			med, mad := medianMAD(rs)
			medians[c][l] = med
			mads[c][l] = mad
			trials[c][l] = rs
		}
	}

	var bits bitBuilder

	// (1) V1 bits — re-emit by inlining Quantize's logic so v1 and v2
	// share the same head bytes; this lets reliability data measured
	// against V1 transfer to V2 without re-enrolling.
	for l := 0; l < m.NumLoops; l++ {
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				bits.appendBit(medians[a][l] > medians[b][l])
			}
		}
	}
	for l := 0; l < m.NumLoops; l++ {
		col := make([]float64, m.NumCores)
		for c := 0; c < m.NumCores; c++ {
			col[c] = medians[c][l]
		}
		gm := grandMedian(col)
		for c := 0; c < m.NumCores; c++ {
			bits.appendBit(medians[c][l] > gm)
		}
	}
	for l := 0; l < m.NumLoops; l++ {
		col := make([]float64, m.NumCores)
		for c := 0; c < m.NumCores; c++ {
			col[c] = cvOf(trials[c][l])
		}
		gm := grandMedian(col)
		p75 := percentile(col, 0.75)
		for c := 0; c < m.NumCores; c++ {
			cv := cvOf(trials[c][l])
			bits.appendBit(cv > gm)
			bits.appendBit(cv > p75)
		}
	}
	for l := 0; l < m.NumLoops; l++ {
		gaps := make([]float64, 0, m.NumCores*(m.NumCores-1)/2)
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				g := medians[a][l] - medians[b][l]
				if g < 0 {
					g = -g
				}
				gaps = append(gaps, g)
			}
		}
		medGap := grandMedian(gaps)
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				g := medians[a][l] - medians[b][l]
				if g < 0 {
					g = -g
				}
				bits.appendBit(g > medGap)
			}
		}
	}

	// (2) Baseline-residual gray-code: per-cell residual bucketed
	// into eight reflected-binary buckets. Buckets are spaced at
	// {-2, -1, -0.5, 0, +0.5, +1, +2} σ_baseline_MAD relative to
	// baseline.median; bucket index ∈ [0, 7] is gray-encoded so a
	// one-bucket drift flips exactly one bit. If baseline is nil
	// (enrolment-time call) the residual is forced to zero so all
	// 12 cells emit bucket 4 → "011" gray.
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			level := residualBucket(medians[c][l], baseline, c, l)
			gray := level ^ (level >> 1)
			bits.appendBit(gray&1 != 0)
			bits.appendBit(gray&2 != 0)
			bits.appendBit(gray&4 != 0)
		}
	}

	// (3) Sub-window temporal pattern: split each cell's trial
	// sequence into four equal windows, emit one bit per window:
	// "median(window) > cell median". For 32 trials this yields
	// windows of 8 trials each — long enough to average out single-
	// trial jitter, short enough to expose slow DVFS oscillations
	// that are specific to the host's thermal package.
	const numWindows = 4
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			rs := trials[c][l]
			if len(rs) < numWindows {
				for w := 0; w < numWindows; w++ {
					bits.appendBit(false)
				}
				continue
			}
			cellMed := medians[c][l]
			win := len(rs) / numWindows
			for w := 0; w < numWindows; w++ {
				lo := w * win
				hi := lo + win
				if w == numWindows-1 {
					hi = len(rs)
				}
				wm, _ := medianMAD(rs[lo:hi])
				bits.appendBit(wm > cellMed)
			}
		}
	}

	// (4) Cross-loop ratio gray-code: for each unordered loop pair
	// and each core, encode the ratio of medians as a 3-bit gray code
	// against thresholds 0.7, 0.85, 0.95, 1.05, 1.18, 1.4, 1.7. The
	// thresholds are dimensionless and were chosen so that the
	// median ratio for healthy Altras lands near the centre buckets;
	// bucketing on log-ratio would be cleaner but adds a math.Log
	// call per bit for negligible gain at this scale.
	loopPairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, lp := range loopPairs {
		la, lb := lp[0], lp[1]
		for c := 0; c < m.NumCores; c++ {
			ratio := safeRatio(medians[c][la], medians[c][lb])
			level := ratioBucket(ratio)
			gray := level ^ (level >> 1)
			bits.appendBit(gray&1 != 0)
			bits.appendBit(gray&2 != 0)
			bits.appendBit(gray&4 != 0)
		}
	}

	packed := bits.bytes()
	h := sha3.New256()
	h.Write(packed)
	h.Write([]byte{byte(bits.length), 0x02 /* version tag */})
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

// residualBucket maps a current cell median to one of eight buckets
// using baseline-relative thresholds. Returns 4 (the centre bucket)
// when no baseline is supplied, which is the correct enrolment-time
// behaviour because the cell is its own reference.
func residualBucket(current float64, baseline *Baseline, core, loop int) uint8 {
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
	// Floor MAD at 0.2% of the baseline median to avoid runaway
	// z-scores on very-stable cells (matches THRESHOLDS.madFloorRatio
	// in baseline.go; we hard-code the constant rather than import it
	// so this file stays self-contained).
	floor := bMed * 0.002
	if bMAD < floor {
		bMAD = floor
	}
	z := (current - bMed) / bMAD
	switch {
	case z <= -2:
		return 0
	case z <= -1:
		return 1
	case z <= -0.5:
		return 2
	case z <= 0:
		return 3
	case z <= 0.5:
		return 4
	case z <= 1:
		return 5
	case z <= 2:
		return 6
	default:
		return 7
	}
}

// safeRatio returns a/b when b is non-zero, 1.0 otherwise. The 1.0
// fallback is the natural identity for ratio-bucketing and avoids
// introducing infinity-shaped poison values into the bit vector.
func safeRatio(a, b float64) float64 {
	if b == 0 {
		return 1
	}
	return a / b
}

// ratioBucket maps a dimensionless ratio to one of eight buckets via
// fixed multiplicative thresholds. Bucket centres span roughly the
// range 0.5×..2× which covers all observed loop-pair ratios on Altra,
// Cascade Lake, and Ampere One in our reference data.
func ratioBucket(r float64) uint8 {
	switch {
	case r <= 0.7:
		return 0
	case r <= 0.85:
		return 1
	case r <= 0.95:
		return 2
	case r <= 1.05:
		return 3
	case r <= 1.18:
		return 4
	case r <= 1.4:
		return 5
	case r <= 1.7:
		return 6
	default:
		return 7
	}
}

// SelectReliableBits returns the indices, into a fingerprint produced
// by QuantizeV2 (or any quantiser), of those bit positions whose
// per-bit BER across the enrolment cycles is at most maxBER. The
// returned slice is sorted ascending so the order is reproducible
// across enrolments. A typical maxBER for code-offset fuzzy
// extraction is 0.02 — corresponding to ~2% per-bit error, well
// inside the correction radius of a small BCH(127, k, t) block code.
//
// fps must contain at least two cycles; the first cycle is taken as
// the reference (its bits are the "should-be" values), and bits are
// counted as flipped if they differ in any subsequent cycle.
func SelectReliableBits(fps []Fingerprint, maxBER float64) []int {
	if len(fps) < 2 {
		return nil
	}
	bitLen := fps[0].Length
	for _, fp := range fps {
		if fp.Length != bitLen {
			return nil
		}
	}
	flips := make([]int, bitLen)
	for c := 1; c < len(fps); c++ {
		for b := 0; b < bitLen; b++ {
			if bitOf(fps[0].Bits, b) != bitOf(fps[c].Bits, b) {
				flips[b]++
			}
		}
	}
	denom := float64(len(fps) - 1)
	out := make([]int, 0, bitLen)
	for b := 0; b < bitLen; b++ {
		if float64(flips[b])/denom <= maxBER {
			out = append(out, b)
		}
	}
	sort.Ints(out)
	return out
}

// bitOf returns bit position b from a packed little-endian byte slice.
// Mirrors bitBuilder's packing so callers reading bits back see the
// same order the quantiser appended them in.
func bitOf(buf []byte, b int) int {
	if b>>3 >= len(buf) {
		return 0
	}
	return int((buf[b>>3] >> uint(b&7)) & 1)
}
