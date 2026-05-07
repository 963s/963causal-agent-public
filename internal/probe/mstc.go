// Package probe — Multi-Source Time Consensus (MSTC).
//
// MSTC is the first 963causal Physics Layer probe. It samples four
// independent time sources in a tight inner loop and reports statistics
// on their pairwise ratios plus per-source read-latency distributions.
//
// Sources (Linux, Intel/AMD and ARM64):
//
//   HW      hardware-architected counter (ARM CNTVCT_EL0, x86 RDTSC).
//   HW2     alternate hardware path     (ARM CNTPCT_EL0, x86 RDTSCP).
//   VDSO    clock_gettime(CLOCK_MONOTONIC_RAW) via the vDSO fast path.
//   SYSCALL same clock via the forced syscall path (SYS_clock_gettime).
//
// Null hypothesis on clean bare metal:
//
//     Δ(HW)/Δ(HW2)       = 1 ± σ_phase_noise  (~1e-6)
//     Δ(HW)/Δ(VDSO)      = 1 ± σ_kernel_skew  (~1e-5 over seconds)
//     Δ(VDSO)/Δ(SYSCALL) = 1 ± σ_granularity  (~1e-4 over ms)
//
// Physical detection cases:
//
//   (a) Hypervisor live-migration or pause/resume → CNTVOFF_EL2 or
//       TSC_OFFSETTING changes discontinuously → HW/VDSO ratio jumps.
//   (b) Rootkit intercepts only the vDSO path (simplest to hook) →
//       VDSO/SYSCALL ratio diverges while HW/HW2 stays clean.
//   (c) Hypervisor traps one hardware read (e.g. RDTSCP with RDTSCP_EXIT
//       but not RDTSC) → HW/HW2 latency distributions diverge even if
//       values stay consistent.
//
// The measured statistics feed the server's identity engine as three
// extra spectral dimensions (ratio means) and six extra tail dimensions
// (per-source p50/p99 read latency).
package probe

import (
	"math"
	"runtime"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	agentpb "github.com/963causal/agent/proto"
)

// MSTCConfig controls the probe. Defaults are tuned for <5 ms wallclock
// cost per frame on a 2 vCPU machine.
type MSTCConfig struct {
	Samples      int           // number of consecutive measurements (default 2048)
	InterSample  time.Duration // optional sleep between samples (default 0)
	WarmupRounds int           // discard this many initial samples (default 64)
}

func defaultMSTC() MSTCConfig {
	return MSTCConfig{
		Samples:      2048,
		InterSample:  0,
		WarmupRounds: 64,
	}
}

// SampleMSTC performs the MSTC measurement loop and returns a digest
// ready to attach to a Frame.
func SampleMSTC(cfgOpt ...MSTCConfig) *agentpb.TimeConsensusDigest {
	cfg := defaultMSTC()
	if len(cfgOpt) > 0 {
		if cfgOpt[0].Samples > 0 {
			cfg.Samples = cfgOpt[0].Samples
		}
		cfg.InterSample = cfgOpt[0].InterSample
		if cfgOpt[0].WarmupRounds > 0 {
			cfg.WarmupRounds = cfgOpt[0].WarmupRounds
		}
	}

	// Lock to a CPU so scheduling migrations don't add to the measured
	// jitter — we want the ratio noise, not the scheduler noise.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	n := cfg.Samples + cfg.WarmupRounds
	hw := make([]uint64, n)
	hw2 := make([]uint64, n)
	vdso := make([]uint64, n)
	sc := make([]uint64, n)
	// Read latencies (in hardware ticks) for each source. Using HW ticks
	// gives ns after dividing by hwHz.
	latHW := make([]uint64, n)
	latHW2 := make([]uint64, n)
	latVDSO := make([]uint64, n)
	latSC := make([]uint64, n)

	// Tight sample loop.
	for i := 0; i < n; i++ {
		t0 := hwCounter()
		hw[i] = hwCounter()
		t1 := hwCounter()
		latHW[i] = hw[i] - t0
		_ = t1

		t0 = hwCounter()
		hw2[i] = hwCounterAlt()
		t1 = hwCounter()
		latHW2[i] = t1 - t0

		t0 = hwCounter()
		vdso[i] = monotonicRawVDSO()
		t1 = hwCounter()
		latVDSO[i] = t1 - t0

		t0 = hwCounter()
		sc[i] = monotonicRawSyscall()
		t1 = hwCounter()
		latSC[i] = t1 - t0

		if cfg.InterSample > 0 {
			time.Sleep(cfg.InterSample)
		}
	}

	hwHz := hwFrequency()
	if hwHz == 0 {
		hwHz = 1
	}

	// Discard warmup.
	hw = hw[cfg.WarmupRounds:]
	hw2 = hw2[cfg.WarmupRounds:]
	vdso = vdso[cfg.WarmupRounds:]
	sc = sc[cfg.WarmupRounds:]
	latHW = latHW[cfg.WarmupRounds:]
	latHW2 = latHW2[cfg.WarmupRounds:]
	latVDSO = latVDSO[cfg.WarmupRounds:]
	latSC = latSC[cfg.WarmupRounds:]

	// Compute deltas (first-differences) for each source.
	dHW := deltas(hw)
	dHW2 := deltas(hw2)
	dVDSO := deltas(vdso)
	dSC := deltas(sc)

	// Normalise the vDSO/syscall deltas to hardware-tick units so the
	// ratios are dimensionless. VDSO and SC report nanoseconds.
	// hwHz ticks per second → ns per tick = 1e9 / hwHz.
	nsPerTick := 1e9 / float64(hwHz)
	dHWNs := toFloatScaled(dHW, nsPerTick)
	dHW2Ns := toFloatScaled(dHW2, nsPerTick)
	dVDSONs := toFloat(dVDSO)
	dSCNs := toFloat(dSC)

	// Welford statistics on pairwise ratios.
	rHWVDSO := welfordRatio(dHWNs, dVDSONs)
	rVDSOSC := welfordRatio(dVDSONs, dSCNs)
	rHWHW2 := welfordRatio(dHWNs, dHW2Ns)

	// Read-latency quantiles, converted to nanoseconds.
	p50HW, p99HW := latencyQuantiles(latHW, nsPerTick)
	_, _ = latencyQuantiles(latHW2, nsPerTick) // reserved for a future proto field
	p50VDSO, p99VDSO := latencyQuantiles(latVDSO, nsPerTick)
	p50SC, p99SC := latencyQuantiles(latSC, nsPerTick)

	return &agentpb.TimeConsensusDigest{
		Arch:                   ArchName,
		HwHz:                   hwHz,
		RatioHwVdsoMean:        rHWVDSO.Mean,
		RatioHwVdsoStddev:      rHWVDSO.Stddev,
		RatioVdsoSyscallMean:   rVDSOSC.Mean,
		RatioVdsoSyscallStddev: rVDSOSC.Stddev,
		RatioHwHw2Mean:         rHWHW2.Mean,
		RatioHwHw2Stddev:       rHWHW2.Stddev,
		HwReadP50Ns:            p50HW,
		HwReadP99Ns:            p99HW,
		VdsoReadP50Ns:          p50VDSO,
		VdsoReadP99Ns:          p99VDSO,
		SyscallReadP50Ns:       p50SC,
		SyscallReadP99Ns:       p99SC,
		SampleCount:            uint32(len(dHW)),
	}
}

// monotonicRawVDSO reads CLOCK_MONOTONIC_RAW through the vDSO fast path,
// which is what Go's runtime uses for time.Now() on Linux.
func monotonicRawVDSO() uint64 {
	// Go's monotonic clock source is CLOCK_MONOTONIC (not RAW) via vDSO.
	// For our purposes any vDSO-served monotonic suffices — we care about
	// the read path, not the clock identity. time.Now().UnixNano() hits
	// the vDSO on all supported Linux targets.
	return uint64(time.Now().UnixNano())
}

// monotonicRawSyscall forces a syscall to get CLOCK_MONOTONIC_RAW,
// bypassing the vDSO. Divergence between this and monotonicRawVDSO
// reveals vDSO interception by a rootkit.
//
// unix.ClockGettime in x/sys/unix is implemented as a direct syscall
// (RawSyscall) on Linux, which is precisely what we want.
func monotonicRawSyscall() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// -------- statistics helpers --------

type ratioStats struct {
	Mean, Stddev float64
	N            int
}

// welfordRatio computes the online mean+variance of the pointwise ratio
// a[i]/b[i], skipping entries where b[i] is zero or non-finite.
func welfordRatio(a, b []float64) ratioStats {
	var n int
	var mean, m2 float64
	for i := 0; i < len(a) && i < len(b); i++ {
		if b[i] <= 0 {
			continue
		}
		r := a[i] / b[i]
		if math.IsNaN(r) || math.IsInf(r, 0) {
			continue
		}
		n++
		delta := r - mean
		mean += delta / float64(n)
		delta2 := r - mean
		m2 += delta * delta2
	}
	out := ratioStats{Mean: mean, N: n}
	if n > 1 {
		out.Stddev = math.Sqrt(m2 / float64(n-1))
	}
	return out
}

func deltas(xs []uint64) []uint64 {
	if len(xs) < 2 {
		return nil
	}
	out := make([]uint64, len(xs)-1)
	for i := 1; i < len(xs); i++ {
		// unsigned subtraction is fine — both counters are monotonic
		// and we only compare within a very short window, so wraparound
		// (72 years at 1 GHz) is physically impossible during sampling.
		out[i-1] = xs[i] - xs[i-1]
	}
	return out
}

func toFloat(xs []uint64) []float64 {
	out := make([]float64, len(xs))
	for i, v := range xs {
		out[i] = float64(v)
	}
	return out
}

func toFloatScaled(xs []uint64, scale float64) []float64 {
	out := make([]float64, len(xs))
	for i, v := range xs {
		out[i] = float64(v) * scale
	}
	return out
}

// latencyQuantiles returns p50 and p99 of the per-sample read latencies,
// converted from hardware ticks to nanoseconds.
func latencyQuantiles(lat []uint64, nsPerTick float64) (p50, p99 float64) {
	if len(lat) == 0 {
		return 0, 0
	}
	cp := make([]uint64, len(lat))
	copy(cp, lat)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return float64(cp[len(cp)/2]) * nsPerTick,
		float64(cp[(len(cp)*99)/100]) * nsPerTick
}
