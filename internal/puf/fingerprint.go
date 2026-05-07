package puf

import (
	"fmt"
	"math"
	"runtime"
	"sort"
	"time"
)

// Config controls a fingerprint measurement cycle. Defaults are tuned for
// a 4-vCPU Ampere Altra guest; callers on richer hardware can increase
// Trials to reduce noise, or lower TargetLoopMs to shorten the cycle at
// the cost of per-trial accuracy.
type Config struct {
	// Trials is the number of (core, loop) repetitions per cell. More
	// trials means a tighter median at the cost of a longer total cycle.
	// Zero defaults to DefaultTrials.
	Trials int

	// WarmupTrials is the number of discarded trials per (core, loop)
	// pair at the start of each cycle. They exist to stabilise CPU DVFS
	// state and caches before any measurement is recorded.
	WarmupTrials int

	// TargetLoopMs is the approximate wall-clock duration of a single loop
	// in milliseconds. Keeping this short (1-5 ms) means a full cycle on
	// 4 cores × 3 loops × 32 trials fits well under ten seconds.
	TargetLoopMs int

	// Cores lists the logical CPU ids to probe. Empty means "all cores
	// reported by runtime.NumCPU()". Deterministic ordering is preserved.
	Cores []int
}

// DefaultTrials is the number of scored trials per (core, loop) cell in the
// default cycle. 32 trials give us a comfortable median at ~4-5 seconds
// total wall-clock on 4 cores.
const DefaultTrials = 32

// DefaultWarmupTrials is the number of discarded trials used to stabilise
// CPU frequency governor and caches before scoring.
const DefaultWarmupTrials = 4

// DefaultTargetLoopMs is the default per-loop wall-clock budget. 3 ms is
// short enough to keep total cycle time under 5s on 4 cores, long enough
// that timer jitter is a small fraction of each sample.
const DefaultTargetLoopMs = 3

// withDefaults returns a copy of cfg with zero-valued fields replaced by
// the package defaults. Callers always work through this helper so the
// default policy lives in one place.
func (c Config) withDefaults() Config {
	if c.Trials <= 0 {
		c.Trials = DefaultTrials
	}
	if c.WarmupTrials <= 0 {
		c.WarmupTrials = DefaultWarmupTrials
	}
	if c.TargetLoopMs <= 0 {
		c.TargetLoopMs = DefaultTargetLoopMs
	}
	if len(c.Cores) == 0 {
		n := numLogicalCores()
		c.Cores = make([]int, n)
		for i := range c.Cores {
			c.Cores[i] = i
		}
	}
	return c
}

// Measure runs a full fingerprint cycle and returns the raw Matrix. The
// caller typically feeds the matrix into Quantize to produce a Fingerprint
// and into Summarise to produce the accompanying Stats. Measure does not
// itself produce a fingerprint because the raw matrix is useful for
// diagnostics (puf-smoke dumps it) and because the quantisation strategy
// may evolve independently of the measurement layer.
//
// Measurement is sequential across cores by design: running cores in
// parallel would share L3 and memory bandwidth, polluting the per-core
// signal with contention noise. Sequential measurement preserves the
// per-core frequency and latency signal we want to fingerprint.
func Measure(cfg Config) (Matrix, error) {
	cfg = cfg.withDefaults()

	if runtime.GOOS != "linux" {
		return Matrix{}, fmt.Errorf("puf: measurement requires Linux (got %s)", runtime.GOOS)
	}
	if len(cfg.Cores) == 0 {
		return Matrix{}, fmt.Errorf("puf: no cores available")
	}

	startedAt := time.Now()
	cores := append([]int(nil), cfg.Cores...)
	sort.Ints(cores)

	numCores := len(cores)
	numLoops := len(AllLoops)
	numTrials := cfg.Trials

	samples := make([][][]Sample, numCores)
	for c := range samples {
		samples[c] = make([][]Sample, numLoops)
		for l := range samples[c] {
			samples[c][l] = make([]Sample, numTrials)
		}
	}

	for cIdx, core := range cores {
		if err := measureCore(core, cIdx, cfg, samples); err != nil {
			return Matrix{}, err
		}
	}

	return Matrix{
		NumCores:  numCores,
		NumLoops:  numLoops,
		NumTrials: numTrials,
		Samples:   samples,
		StartedAt: startedAt,
		Duration:  time.Since(startedAt),
	}, nil
}

// measureCore runs all loop kinds for all trials on a single core, in a
// dedicated OS thread that is pinned to that core for the duration of the
// measurement. The thread is released (via runtime.UnlockOSThread) after
// the last trial.
//
// cIdx is the destination slot in samples (distinct from the physical core
// id in cfg.Cores, which may be sparse if the caller restricted the set).
func measureCore(core, cIdx int, cfg Config, samples [][][]Sample) error {
	// Pinning is observed by a fresh OS thread. LockOSThread plus a goroutine
	// guarantees that if something goes wrong, the tainted thread dies with
	// the goroutine instead of leaking a pinned thread back into the pool.
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := pinToCore(core); err != nil {
			done <- err
			return
		}

		for lIdx, kind := range AllLoops {
			iters := iterCountFor(kind, cfg.TargetLoopMs)

			for w := 0; w < cfg.WarmupTrials; w++ {
				_ = measureOnce(core, kind, -1, iters)
			}

			for t := 0; t < cfg.Trials; t++ {
				samples[cIdx][lIdx][t] = measureOnce(core, kind, t, iters)
			}
		}
		done <- nil
	}()

	return <-done
}

// Summarise reduces a Matrix to per-(core,loop) statistics that the server
// can store alongside the fingerprint. Median and MAD are preferred over
// mean and stddev because a single thermal transient can skew the mean
// significantly while leaving the median nearly untouched.
func Summarise(m Matrix) Stats {
	var out Stats
	out.NumCores = m.NumCores
	out.NumLoops = m.NumLoops
	out.NumTrials = m.NumTrials
	out.Arch = runtime.GOARCH
	out.DurationMs = float64(m.Duration.Nanoseconds()) / 1e6

	out.PerCoreLoop = make([]CoreStats, 0, m.NumCores*m.NumLoops)
	for c := 0; c < m.NumCores; c++ {
		for l := 0; l < m.NumLoops; l++ {
			col := m.Samples[c][l]
			rates := make([]float64, len(col))
			for i := range col {
				rates[i] = col[i].ItersPerSec()
			}
			cs := CoreStats{
				Core:       col[0].Core,
				Loop:       col[0].Loop,
				NumSamples: len(rates),
			}
			cs.Median, cs.MAD = medianMAD(rates)
			cs.CV = cvOf(rates)
			cs.Min, cs.Max = minMax(rates)
			out.PerCoreLoop = append(out.PerCoreLoop, cs)
		}
	}
	return out
}

func medianMAD(xs []float64) (median, mad float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	median = cp[len(cp)/2]
	dev := make([]float64, len(cp))
	for i, v := range cp {
		d := v - median
		if d < 0 {
			d = -d
		}
		dev[i] = d
	}
	sort.Float64s(dev)
	mad = dev[len(dev)/2]
	return
}

// cvOf returns the coefficient of variation (stddev/mean) using Welford's
// online algorithm. The two-pass / naive "E[X²] - E[X]²" formulation loses
// catastrophic precision when the magnitudes (iters/sec) are in the 1e8
// range — E[X²] and E[X]² are both ≈ 1e16 and their difference cancels out
// most significant digits. Welford is numerically stable and cheap enough
// that the readability cost is trivial.
func cvOf(xs []float64) float64 {
	n := len(xs)
	if n < 2 {
		return 0
	}
	var mean, m2 float64
	for i, x := range xs {
		delta := x - mean
		mean += delta / float64(i+1)
		m2 += delta * (x - mean)
	}
	if mean == 0 {
		return 0
	}
	variance := m2 / float64(n-1)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance) / mean
}

func minMax(xs []float64) (mn, mx float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	mn, mx = xs[0], xs[0]
	for _, x := range xs[1:] {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	return
}
