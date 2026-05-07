package puf

import (
	"fmt"
	"math"
	"runtime"
	"time"
)

// Verdict thresholds for CompareToBaseline. These values are starting
// points derived from a handful of smoke runs on Ampere Altra guests;
// they are expected to be tuned once real fleet data is collected in W5a.
//
//	PassMaxZ     — every cell's |z| must be <= this for PASS
//	PassMeanZ    — the mean |z| across cells must be <= this for PASS
//	DriftMaxZ    — above this any cell drops the verdict to DRIFT
//	DriftMaxRatio — relative drift > this escalates even if z is small
//	TamperMaxZ   — above this the verdict escalates to TAMPER
//	TamperMaxRatio — large relative drift (silicon swap) -> TAMPER
const (
	PassMaxZ       = 5.0
	PassMeanZ      = 1.5
	DriftMaxZ      = 15.0
	DriftMaxRatio  = 0.05 // 5 % relative drift
	TamperMaxZ     = 40.0
	TamperMaxRatio = 0.15 // 15 % relative drift indicates different silicon
)

// madFloor prevents div-by-zero when a baseline cell has effectively no
// variance — expressed as a fraction of the baseline median. Within-trial
// MAD drastically under-estimates cross-run (cross-second) drift on very
// latency-bound loops like mem-stride, whose baseline MAD can be 0.003%
// while real inter-attestation drift is around 0.2%. Clamping the MAD
// floor at 0.2% of the median calibrates the z-score to the cross-run
// noise floor observed on Ampere Altra guests; fleet calibration in W5a
// will produce per-arch refinements.
const madFloorRatio = 0.002

// NewBaseline consumes a Matrix and produces a Baseline suitable for
// long-term storage. Callers pass the matrix produced by Measure at
// enrollment time. The returned Baseline is safe to serialise as JSON.
//
// NewBaseline is a thin wrapper around Summarise: the two share an
// underlying representation so future fields (for example, per-cell
// skewness or persistence-noise exponents) can be added without a second
// measurement pass.
func NewBaseline(m Matrix) Baseline {
	stats := Summarise(m)
	return Baseline{
		PerCoreLoop: stats.PerCoreLoop,
		NumCores:    m.NumCores,
		NumLoops:    m.NumLoops,
		NumTrials:   m.NumTrials,
		Arch:        runtime.GOARCH,
		CreatedAt:   time.Now().UTC(),
	}
}

// CompareToBaseline scores the current stats against an enrolled baseline
// and returns a Report containing per-cell drifts, aggregate metrics, and
// a verdict. The verdict policy is:
//
//	PASS   : max |z| <= PassMaxZ AND mean |z| <= PassMeanZ
//	         AND max |ratio| <= DriftMaxRatio
//	TAMPER : max |z| >= TamperMaxZ OR max |ratio| >= TamperMaxRatio
//	DRIFT  : everything else
//
// The policy is intentionally order-sensitive: a host whose relative drift
// jumps into the tamper band is classified TAMPER even if the z-score is
// small because the baseline had very tight MAD (a cloned VM with a
// different but also tight distribution would present this way).
//
// Geometry mismatches (different core or loop count) return an error
// rather than a verdict so that the control plane cannot accidentally
// paper over a structural change (e.g. attacker forces the agent to see
// fewer cores).
func CompareToBaseline(current Stats, baseline Baseline) (Report, error) {
	if current.NumCores != baseline.NumCores || current.NumLoops != baseline.NumLoops {
		return Report{}, fmt.Errorf("puf: geometry mismatch: baseline=%dc/%dl, current=%dc/%dl",
			baseline.NumCores, baseline.NumLoops, current.NumCores, current.NumLoops)
	}
	if len(current.PerCoreLoop) != len(baseline.PerCoreLoop) {
		return Report{}, fmt.Errorf("puf: cell count mismatch: baseline=%d, current=%d",
			len(baseline.PerCoreLoop), len(current.PerCoreLoop))
	}

	// Build a lookup from (core, loop) to baseline cell so we don't rely on
	// slice ordering surviving transport.
	base := make(map[cellKey]CoreStats, len(baseline.PerCoreLoop))
	for _, cs := range baseline.PerCoreLoop {
		base[cellKey{cs.Core, cs.Loop}] = cs
	}

	cells := make([]CellDrift, 0, len(current.PerCoreLoop))
	var sumAbsZ, maxAbsZ, maxAbsRatio float64
	for _, cur := range current.PerCoreLoop {
		b, ok := base[cellKey{cur.Core, cur.Loop}]
		if !ok {
			return Report{}, fmt.Errorf("puf: baseline missing cell core=%d loop=%s", cur.Core, cur.Loop)
		}
		floor := b.Median * madFloorRatio
		effMAD := b.MAD
		if effMAD < floor {
			effMAD = floor
		}
		var z float64
		if effMAD > 0 {
			z = (cur.Median - b.Median) / effMAD
		}
		var ratio float64
		if b.Median > 0 {
			ratio = (cur.Median - b.Median) / b.Median
		}
		cells = append(cells, CellDrift{
			Core:           cur.Core,
			Loop:           cur.Loop,
			BaselineMedian: b.Median,
			CurrentMedian:  cur.Median,
			BaselineMAD:    b.MAD,
			Ratio:          ratio,
			Z:              z,
		})
		if absZ := math.Abs(z); absZ > maxAbsZ {
			maxAbsZ = absZ
		}
		sumAbsZ += math.Abs(z)
		if absR := math.Abs(ratio); absR > maxAbsRatio {
			maxAbsRatio = absR
		}
	}
	meanAbsZ := sumAbsZ / float64(len(cells))

	verdict := classify(maxAbsZ, meanAbsZ, maxAbsRatio)

	return Report{
		Cells:       cells,
		MaxAbsZ:     maxAbsZ,
		MeanAbsZ:    meanAbsZ,
		MaxAbsRatio: maxAbsRatio,
		Verdict:     verdict,
	}, nil
}

func classify(maxAbsZ, meanAbsZ, maxAbsRatio float64) string {
	if maxAbsZ >= TamperMaxZ || maxAbsRatio >= TamperMaxRatio {
		return "TAMPER"
	}
	if maxAbsZ <= PassMaxZ && meanAbsZ <= PassMeanZ && maxAbsRatio <= DriftMaxRatio {
		return "PASS"
	}
	return "DRIFT"
}

type cellKey struct {
	core int
	loop LoopKind
}
