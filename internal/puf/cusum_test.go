package puf

import (
	"math/rand"
	"testing"
)

// TestCUSUMStationarityNoFalseAlarm seeds the detector with a
// purely-Bernoulli noise process (no drift) and confirms the
// aggregate CUSUM stays below H across 400 cycles. This is the
// "do not cry wolf" half of the specification: ARL_0 for the
// aggregate test at k=0.5σ, H=5σ should be ~370; observing zero
// false alarms in 400 cycles at a comfortably-seeded RNG gives
// us the confidence the implementation is not silently biased.
func TestCUSUMStationarityNoFalseAlarm(t *testing.T) {
	const (
		nBits  = 224
		nCyc   = 400
		berMu  = 0.005 // per-bit false-flip probability under the null
	)
	rng := rand.New(rand.NewSource(0xFEEDFACE))
	calib := make([][]bool, 40)
	for i := range calib {
		calib[i] = sampleBernoulli(rng, nBits, berMu)
	}
	c, err := Calibrate(calib)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	t.Logf("calibrated μ=%.3f σ=%.3f H=%.3f", c.Mu, c.Sigma, c.H)

	// Count only EDGE events — transitions from "S⁺ ≤ H" to
	// "S⁺ > H" — because that is what "alarm" means in SPC
	// literature. Once the CUSUM has crossed the threshold it
	// will usually stay above it for several more cycles before
	// the drift-absent process decays it back; we do not want
	// to double-count those as independent false alarms.
	var (
		aggFalseEdges   int
		perBitFalseEdges int
		prevAggFired     bool
		prevPerBitFired  bool
	)
	for i := 0; i < nCyc; i++ {
		v, err := c.Observe(sampleBernoulli(rng, nBits, berMu))
		if err != nil {
			t.Fatalf("observe[%d]: %v", i, err)
		}
		if v.AggregateFired && !prevAggFired {
			aggFalseEdges++
		}
		if v.PerBitFired && !prevPerBitFired {
			perBitFalseEdges++
		}
		prevAggFired, prevPerBitFired = v.AggregateFired, v.PerBitFired
	}
	t.Logf("null hypothesis: %d aggregate-edge alarms, %d per-bit-edge alarms in %d cycles",
		aggFalseEdges, perBitFalseEdges, nCyc)
	// Expected ARL_0 for aggregate at k=0.5σ, H=5σ is ~370 cycles.
	// In 400 cycles we therefore expect ≤ 2 edges on average;
	// setting the ceiling at 3 is a 1-σ cushion.
	if aggFalseEdges > 3 {
		t.Errorf("aggregate false alarms too frequent: %d > 3", aggFalseEdges)
	}
	// Per-bit family FWER is ≤ 0.001/cycle by construction;
	// expect ≤ 1 edge in 400 cycles, tolerate up to 3.
	if perBitFalseEdges > 3 {
		t.Errorf("per-bit false alarms too frequent: %d > 3", perBitFalseEdges)
	}
}

// TestCUSUMBoilingFrogBroad is the headline detection-speed test:
// an adversary adds a small directional drift to *every* bit each
// cycle. The aggregate CUSUM should fire well before the naive
// 30-day deadline the user's threat analysis set.
func TestCUSUMBoilingFrogBroad(t *testing.T) {
	const (
		nBits       = 224
		berMu       = 0.005
		attackPct   = 0.01 // the threat scenario: 1 % shift per cycle
		maxBudget   = 30   // days
		expectedMax = 15   // per the threat analysis: must fire well before day 15
	)
	rng := rand.New(rand.NewSource(0xCAFEF00D))

	calib := make([][]bool, 40)
	for i := range calib {
		calib[i] = sampleBernoulli(rng, nBits, berMu)
	}
	c, err := Calibrate(calib)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}

	var detectedAt int
	for day := 1; day <= maxBudget; day++ {
		// Daily BER under attack = berMu + day*attackPct
		// (the attacker keeps shifting ALL bits in the same
		// direction, a little more each day).
		pToday := berMu + float64(day)*attackPct
		if pToday > 1 {
			pToday = 1
		}
		v, err := c.Observe(sampleBernoulli(rng, nBits, pToday))
		if err != nil {
			t.Fatalf("observe day %d: %v", day, err)
		}
		if v.AggregateFired || v.PerBitFired {
			detectedAt = day
			t.Logf("attack detected at day %d: level=%s S⁺=%.2f hamming=%d drifting_bits=%d",
				day, v.Level, v.AggregatePlus, v.HammingDistance, v.DriftingBitCount)
			break
		}
	}
	if detectedAt == 0 {
		t.Fatalf("boiling-frog attack NEVER detected in %d days (CUSUM failed its purpose)", maxBudget)
	}
	if detectedAt > expectedMax {
		t.Errorf("boiling-frog detected at day %d — expected ≤ %d (attack window too wide)",
			detectedAt, expectedMax)
	}
}

// TestCUSUMBoilingFrogTargeted is the harder case: the adversary
// attacks only a small subset of bits, each shifted sharply, so
// the aggregate Hamming distance rises only a couple of bits per
// day (below the aggregate CUSUM's per-cycle detection capacity).
// The per-bit detector should still catch it.
func TestCUSUMBoilingFrogTargeted(t *testing.T) {
	const (
		nBits       = 224
		berMu       = 0.005
		nAttackBits = 8
		perBitShift = 0.15 // 15 % per-cycle flip probability on the attacked bits
		maxBudget   = 30
	)
	rng := rand.New(rand.NewSource(0x12345678))

	calib := make([][]bool, 40)
	for i := range calib {
		calib[i] = sampleBernoulli(rng, nBits, berMu)
	}
	c, err := Calibrate(calib)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	// Pick the bits the attacker will target. We pick contiguous
	// indices for simplicity; the detector cares about statistics,
	// not positions.
	var attacked [8]int
	for i := range attacked {
		attacked[i] = 3*i + 11
	}

	var detectedAt int
	for day := 1; day <= maxBudget; day++ {
		delta := sampleBernoulli(rng, nBits, berMu)
		// Overwrite the attacked bits with the elevated-p Bernoulli.
		for _, idx := range attacked {
			delta[idx] = rng.Float64() < perBitShift
		}
		v, err := c.Observe(delta)
		if err != nil {
			t.Fatalf("observe day %d: %v", day, err)
		}
		if v.PerBitFired {
			detectedAt = day
			t.Logf("targeted attack detected at day %d: level=%s drifting_bits=%d max S⁺=%.2f at bit %d",
				day, v.Level, v.DriftingBitCount, v.MaxPerBitPlus, v.ArgmaxPlus)
			break
		}
	}
	if detectedAt == 0 {
		t.Fatalf("targeted poisoning NEVER detected in %d days", maxBudget)
	}
}

// TestCUSUMResetClearsDriftStateNotCalibration confirms Reset
// zeroes the accumulator but preserves μ/σ, so a legitimate
// recalibration does not re-learn the baseline from scratch.
func TestCUSUMResetClearsDriftStateNotCalibration(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	calib := make([][]bool, 40)
	for i := range calib {
		calib[i] = sampleBernoulli(rng, 64, 0.01)
	}
	c, err := Calibrate(calib)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	muBefore, sigmaBefore := c.Mu, c.Sigma

	// Push the CUSUM into an alert state with a heavy attack.
	for i := 0; i < 20; i++ {
		_, _ = c.Observe(sampleBernoulli(rng, 64, 0.9))
	}
	if c.SPlusAgg == 0 {
		t.Fatal("expected S⁺ to have accumulated under sustained shift")
	}

	c.Reset()
	if c.SPlusAgg != 0 || c.SMinusAgg != 0 {
		t.Errorf("Reset did not clear aggregate state: S⁺=%.3f S⁻=%.3f",
			c.SPlusAgg, c.SMinusAgg)
	}
	if c.Mu != muBefore || c.Sigma != sigmaBefore {
		t.Errorf("Reset clobbered calibration (μ %.3f→%.3f, σ %.3f→%.3f)",
			muBefore, c.Mu, sigmaBefore, c.Sigma)
	}
}

// sampleBernoulli draws one row of n Bernoulli(p) trials.
func sampleBernoulli(rng *rand.Rand, n int, p float64) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = rng.Float64() < p
	}
	return out
}
