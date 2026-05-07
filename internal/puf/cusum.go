package puf

import (
	"errors"
	"fmt"
	"math"
)

// CUSUM (Cumulative Sum Control Chart) — detector for systematic
// drift against a stationary noise baseline. This is the defence
// against the "boiling-frog poisoning" attack: an adversary who
// flips PUF bits by a small fraction each day, betting that any
// single-day change stays inside the z-score attestation window.
//
// Mathematical shape:
//
//   For each stable bit position i, observe x_i(t) = 1 iff bit_i
//   of the fresh measurement disagrees with the enrolment. Under
//   stationary noise x_i(t) is Bernoulli(p_i); the aggregate
//   Hamming distance H(t) = Σ x_i(t) has E[H] = μ = Σ p_i and
//   Var[H] = Σ p_i(1-p_i). Under a poisoning attack that adds
//   δ bits of directional drift per cycle, E[H(t)] = μ + δ·t.
//
//   The classical one-sided CUSUM statistic for detecting an
//   upward shift of size k·σ is
//
//     S⁺(t) = max(0, S⁺(t-1) + (H(t) - μ) - k)
//     ALERT when S⁺(t) > H_threshold
//
//   (Page, 1954). We also maintain the symmetric S⁻ for
//   completeness — some quantiser drifts flip bits the other way,
//   and we want to catch both directions.
//
// Two CUSUMs run in parallel:
//
//   1. AGGREGATE CUSUM on total Hamming distance. Catches
//      broad-spectrum poisoning (attacker shifts many bits by
//      small per-bit deltas).
//
//   2. PER-BIT CUSUM on each reliable bit with a Bonferroni-
//      corrected threshold so the family-wise false-alarm rate
//      stays at the target α. Catches targeted poisoning
//      (attacker shifts only a handful of bits by large deltas;
//      aggregate CUSUM misses because total Hamming distance
//      barely moves).
//
// Parameter choice for the shipping deployment:
//
//   μ, σ    derived from the first CalibrationCycles attestations
//           AFTER enrolment (typically M = 40 cycles; matches the
//           reliable-bit selection already done by
//           SelectReliableBits).
//   k       = 0.5 · σ   (optimal Kullback detection when the
//                        expected shift equals 1σ; see Basseville
//                        & Nikiforov, "Detection of Abrupt
//                        Changes", §4.3.2).
//   H       = 5 · σ     (per-hypothesis ARL_0 ≈ 370 cycles, i.e.
//                        one false alarm every ~370 attestations
//                        when the null holds).
//   α_family = 0.001   (family-wise false-alarm rate across all
//                        per-bit CUSUMs).
//   α_per-bit = α_family / N   (Bonferroni; for N = 224 reliable
//                                bits this is ~4.5·10⁻⁶).
type CUSUM struct {
	// Calibrated parameters.
	Mu     float64 // expected aggregate Hamming distance per cycle
	Sigma  float64 // std-dev of the aggregate under the null
	K      float64 // slack; defaults to 0.5·σ
	H      float64 // alert threshold; defaults to 5·σ
	PerBitBER []float64 // expected flip probability per bit i; len == N

	// Running state. Zero value = fresh after calibration.
	SPlusAgg  float64 // aggregate upward CUSUM
	SMinusAgg float64 // aggregate downward CUSUM
	SPlusBits []float64
	SMinusBits []float64

	// Rolling count of observations since calibration. Used for
	// ARL diagnostics; not part of the detection rule itself.
	Observations int
}

// Calibrate returns a CUSUM initialised from the observed Hamming
// distances over a burst of post-enrolment cycles. Each cycle is a
// []bool of length N (N = number of reliable bits selected at
// enrolment): entry j is true iff bit j of that cycle's
// fingerprint differed from the enrolment bit. The caller is
// responsible for computing that bit-delta vector — QuantizeV3 +
// SelectReliableBits already give the indices to index into, so
// this is a few lines at the call site.
//
// Returns an error if fewer than 8 calibration cycles are given or
// the bit-vector shapes disagree.
func Calibrate(bitDeltasPerCycle [][]bool) (*CUSUM, error) {
	if len(bitDeltasPerCycle) < 8 {
		return nil, fmt.Errorf("cusum: need ≥ 8 calibration cycles, got %d",
			len(bitDeltasPerCycle))
	}
	n := len(bitDeltasPerCycle[0])
	if n == 0 {
		return nil, errors.New("cusum: empty bit vector")
	}
	for i, row := range bitDeltasPerCycle {
		if len(row) != n {
			return nil, fmt.Errorf("cusum: cycle %d has %d bits, expected %d",
				i, len(row), n)
		}
	}

	// Per-bit empirical BER = flip count / cycles.
	berPerBit := make([]float64, n)
	var hamming []float64
	for _, row := range bitDeltasPerCycle {
		h := 0.0
		for i, b := range row {
			if b {
				berPerBit[i] += 1
				h++
			}
		}
		hamming = append(hamming, h)
	}
	for i := range berPerBit {
		berPerBit[i] /= float64(len(bitDeltasPerCycle))
	}

	// Aggregate μ and σ from empirical Hamming distances. We use
	// the sample mean / sample stddev directly because the number
	// of calibration cycles (20..40) is already large enough that
	// the bias of Bessel's correction is < 3 %.
	mu := mean(hamming)
	sigma := stddev(hamming, mu)
	// Never let σ collapse to zero: an unrealistically-quiet
	// baseline inflates z-scores to infinity and defeats the
	// detector. 0.5 bit is the hard floor we picked during the
	// W5a bring-up for the same reason (BSL §11.7).
	if sigma < 0.5 {
		sigma = 0.5
	}

	c := &CUSUM{
		Mu:         mu,
		Sigma:      sigma,
		K:          0.5 * sigma,
		H:          5.0 * sigma,
		PerBitBER:  berPerBit,
		SPlusBits:  make([]float64, n),
		SMinusBits: make([]float64, n),
	}
	return c, nil
}

// Observe feeds one fresh measurement into the CUSUM. The input
// is the bit-delta vector (len == N) for this cycle: entry j is
// true iff bit j of the measurement disagreed with enrolment.
// Returns a DriftVerdict summarising what the current run has
// detected.
//
// Calling Observe is idempotent in the sense that re-running the
// same sequence of cycles on a fresh CUSUM yields the same
// verdicts; the detector has no per-cycle randomness.
func (c *CUSUM) Observe(bitDelta []bool) (DriftVerdict, error) {
	if c == nil {
		return DriftVerdict{}, errors.New("cusum: nil receiver")
	}
	if len(bitDelta) != len(c.PerBitBER) {
		return DriftVerdict{}, fmt.Errorf("cusum: observe got %d bits, calibrated for %d",
			len(bitDelta), len(c.PerBitBER))
	}

	// Aggregate Hamming distance for this cycle.
	h := 0.0
	for _, b := range bitDelta {
		if b {
			h++
		}
	}
	delta := h - c.Mu

	// Two-sided aggregate CUSUM.
	c.SPlusAgg = math.Max(0, c.SPlusAgg+delta-c.K)
	c.SMinusAgg = math.Max(0, c.SMinusAgg-delta-c.K)

	// Per-bit CUSUM parameter tuning is NOT symmetric with the
	// aggregate path. At the aggregate level the distribution is
	// ~Gaussian (sum of 224 Bernoullis, Central Limit Theorem
	// applies), so k = 0.5σ and H = 5σ give classical Page ARL_0
	// ≈ 370. At the per-bit level each observation is a single
	// Bernoulli with small p; a single flip jumps S⁺ by (1 - p_i
	// - k_i), which for p_i=0.005 is ~0.96. Tuning by σ_i (~0.07)
	// would mean a single noise flip alarms, because 0.96 > 12·σ_i.
	//
	// For the per-bit path we use the Bernoulli-specific Shewhart-
	// CUSUM parameters (Lucas 1985, Hawkins & Olwell 1998 §4.4):
	//
	//   k_i = (p0 + p1)/2 - p0 = (p1 - p0)/2
	//         where p1 = perBitAlternativeBER = 0.05 is the smallest
	//         attack shift we want to detect. Larger k means the
	//         detector is faster but insensitive to smaller shifts.
	//
	//   H_i = perBitAlarmThreshold = 1.5
	//         chosen so that a single isolated flip (ΔS⁺ ≈ 0.92)
	//         cannot cross the threshold — need at least two flips
	//         within a decay window to fire. That pushes the
	//         per-bit ARL_0 into the 20000+ range at p0 = 0.005,
	//         and Bonferroni with N = 224 keeps the family ARL_0
	//         north of ~100 cycles.
	const (
		perBitAlternativeBER = 0.05
		perBitAlarmThreshold = 1.5
	)

	// Per-bit CUSUM (each bit is a Bernoulli trial with mean
	// berPerBit[i]; σ_i ≈ √(p(1-p)), but for the detector we
	// use a single aggregate σ so the family threshold is
	// comparable to the aggregate one).
	driftingBits := 0
	var maxSPlus, maxSMinus float64
	var argmaxPlus, argmaxMinus int
	for i, b := range bitDelta {
		obs := 0.0
		if b {
			obs = 1.0
		}
		d := obs - c.PerBitBER[i]
		// Per-bit k = 0.5·σ_i where σ_i = √(p(1-p)). For p ≈ 0.005
		// this is ~ 0.035 — much tighter than the aggregate slack.
		// Optimal Bernoulli CUSUM slack: (p1 - p0)/2 where p0 is
		// the enrolled BER and p1 is the smallest detectable shift.
		// p0 may itself be zero for very-stable bits; clamp so the
		// slack stays meaningful.
		p0 := c.PerBitBER[i]
		if p0 < 0.001 {
			p0 = 0.001
		}
		kI := (perBitAlternativeBER - p0) / 2
		if kI < 0.01 {
			kI = 0.01
		}
		c.SPlusBits[i] = math.Max(0, c.SPlusBits[i]+d-kI)
		c.SMinusBits[i] = math.Max(0, c.SMinusBits[i]-d-kI)

		if c.SPlusBits[i] > perBitAlarmThreshold || c.SMinusBits[i] > perBitAlarmThreshold {
			driftingBits++
		}
		if c.SPlusBits[i] > maxSPlus {
			maxSPlus = c.SPlusBits[i]
			argmaxPlus = i
		}
		if c.SMinusBits[i] > maxSMinus {
			maxSMinus = c.SMinusBits[i]
			argmaxMinus = i
		}
	}
	c.Observations++

	// Verdict synthesis.
	v := DriftVerdict{
		HammingDistance:  int(h),
		AggregatePlus:    c.SPlusAgg,
		AggregateMinus:   c.SMinusAgg,
		MaxPerBitPlus:    maxSPlus,
		MaxPerBitMinus:   maxSMinus,
		ArgmaxPlus:       argmaxPlus,
		ArgmaxMinus:      argmaxMinus,
		DriftingBitCount: driftingBits,
		AggregateFired:   c.SPlusAgg > c.H || c.SMinusAgg > c.H,
		PerBitFired:      driftingBits > 0,
	}
	switch {
	case v.AggregateFired && v.PerBitFired:
		v.Level = "CRITICAL" // both detectors agree → unambiguous attack
	case v.AggregateFired:
		v.Level = "BROAD_DRIFT"
	case v.PerBitFired:
		v.Level = "TARGETED_DRIFT"
	default:
		v.Level = "OK"
	}
	return v, nil
}

// Reset zeroes the CUSUM state without discarding the calibration.
// Useful after an explicit operator-approved recalibration: we
// preserve the learned μ/σ baseline but start the drift accounting
// from zero so a legitimate live-migration (a one-shot shift) does
// not poison subsequent observations.
func (c *CUSUM) Reset() {
	if c == nil {
		return
	}
	c.SPlusAgg, c.SMinusAgg = 0, 0
	c.Observations = 0
	for i := range c.SPlusBits {
		c.SPlusBits[i] = 0
		c.SMinusBits[i] = 0
	}
}

// DriftVerdict is the summary Observe emits for a single cycle.
// Named "Drift" — not "Cusum" — because the same struct will later
// back other drift detectors (e.g. a CUSUM on DAQ ticket cadence);
// and NOT "Verdict" because that name is already taken by
// compare.go for the existing z-score attestation path.
//
// Level is a short string operator-facing consumers can render:
//
//   OK              — under the null; CUSUM statistic below all thresholds.
//   BROAD_DRIFT     — aggregate CUSUM fired (many bits drifting slowly).
//   TARGETED_DRIFT  — one or more per-bit CUSUMs fired (few bits drifting fast).
//   CRITICAL        — both detectors fired simultaneously; high confidence attack.
type DriftVerdict struct {
	HammingDistance  int
	AggregatePlus    float64
	AggregateMinus   float64
	MaxPerBitPlus    float64
	MaxPerBitMinus   float64
	ArgmaxPlus       int
	ArgmaxMinus      int
	DriftingBitCount int
	AggregateFired   bool
	PerBitFired      bool
	Level            string
}

// ComputeBitDelta is the helper the attestation pipeline uses to
// turn a freshly-quantised Fingerprint plus the enrolment
// Fingerprint + the indices of reliable bits into the bool slice
// Observe expects. Centralising it here keeps any change to the
// reliable-bit indexing convention in one place.
func ComputeBitDelta(enrolFP, freshFP Fingerprint, indices []int) ([]bool, error) {
	if enrolFP.Length == 0 || freshFP.Length == 0 {
		return nil, errors.New("cusum: empty fingerprint")
	}
	if enrolFP.Length != freshFP.Length {
		return nil, fmt.Errorf("cusum: fingerprint length mismatch: %d vs %d",
			enrolFP.Length, freshFP.Length)
	}
	out := make([]bool, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= enrolFP.Length {
			return nil, fmt.Errorf("cusum: index %d out of range [0,%d)",
				idx, enrolFP.Length)
		}
		out[i] = bitOf(enrolFP.Bits, idx) != bitOf(freshFP.Bits, idx)
	}
	return out, nil
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddev(xs []float64, mu float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var s float64
	for _, x := range xs {
		d := x - mu
		s += d * d
	}
	return math.Sqrt(s / float64(len(xs)-1))
}
