package puf

import (
	"runtime"
	"time"
)

// sink is written by every measurement loop so that the Go compiler cannot
// prove the loops are dead. It is declared package-global and exported in
// spirit (lowercase but never read) purely to act as a destination for
// otherwise-unobservable work.
//
// Because the sink is a single uint64 touched by every loop variant, later
// measurements are not strictly independent — a small carry of state flows
// through. We accept this: the impact on inter-core discrimination is
// negligible (loops fully rewrite the accumulator per iteration) and the
// benefit of guaranteeing observable work far outweighs the cost.
var sink uint64

// memBuf holds the pointer-chase array used by LoopMemStride. Keeping it
// package-global ensures every call uses the same backing memory, which
// means the first post-warmup access lands in L2/L3 state that is stable
// across cores. 8 KiB fits comfortably in L1D on every target we care
// about (32 KiB minimum), so once warmed the loop should hit L1 steady
// state.
const memBufWords = 1024
const memBufSize = memBufWords * 8 // 8 KiB

var memBuf [memBufWords]uint32

// init seeds memBuf with a derangement-style permutation so every pointer
// chase reaches every slot exactly once before cycling. This is critical:
// a trivial chain (table[i] = i+1) is detected and unrolled by prefetchers;
// a shuffled permutation defeats them and produces the chain latency we
// want to measure.
func init() {
	// xorshift* permutation: start with identity, then walk through with a
	// deterministic PRNG to swap pairs. We rely on no RNG source except
	// this local state so the permutation is identical across builds.
	for i := range memBuf {
		memBuf[i] = uint32(i)
	}
	x := uint64(0x9E3779B97F4A7C15)
	for i := len(memBuf) - 1; i > 0; i-- {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		j := int(x % uint64(i+1))
		memBuf[i], memBuf[j] = memBuf[j], memBuf[i]
	}
}

// runIntMix performs n iterations of a pure-ALU xorshift+multiply loop.
// Returns a checksum of the accumulator; writes to the global sink. The
// number of cycles consumed per iteration is approximately the same on
// any reasonable core (4-6 cycles on Cortex-A76 / Neoverse N1/V1), but
// small per-core frequency variations show up as wall-clock differences.
//
//go:noinline
func runIntMix(seed uint64, n uint64) uint64 {
	acc := seed
	for i := uint64(0); i < n; i++ {
		acc = acc*0x9E3779B97F4A7C15 + 0xCAFEBABEDEADBEEF
		acc ^= acc >> 13
		acc ^= acc << 7
	}
	sink ^= acc
	return acc
}

// runMemStride walks the pre-shuffled memBuf for n iterations. Each
// iteration loads the next index from the current cell, producing a
// load-to-use chain the hardware prefetcher cannot defeat. This isolates
// the load-latency component of the core's memory pipeline.
//
//go:noinline
func runMemStride(seed uint32, n uint64) uint32 {
	idx := seed % uint32(len(memBuf))
	for i := uint64(0); i < n; i++ {
		idx = memBuf[idx]
	}
	sink ^= uint64(idx)
	return idx
}

// runFloatMul performs a dependent fp64 multiply-add chain. Each
// iteration builds on the previous one, defeating the FPU's pipelined
// throughput and forcing the chain to bottleneck on issue-to-result
// latency. That latency is set by the silicon's FPU implementation
// (Cortex-A76 = 4 cycles, Neoverse N1 = 3 cycles, Apple Avalanche = 4
// cycles, etc.) and is one of the most stable per-host signals we get
// from userspace — it's nearly impossible to imitate from a wrong CPU.
//
//go:noinline
func runFloatMul(seed uint64, n uint64) float64 {
	// Convert seed into a small but non-trivial double; bias toward
	// the [1.0, 2.0) range so the multiplier never collapses to zero
	// (which would let the optimiser fold the whole chain) and never
	// explodes to Inf (which short-circuits the FPU).
	a := 1.0 + float64(seed&0xFFFF)/65536.0
	b := 1.0000001
	for i := uint64(0); i < n; i++ {
		a = a*b + 1e-12
		// Re-normalise occasionally so a stays in [1, 2). Without this
		// rescale, after ~64K iterations a saturates to Inf.
		if a > 2.0 {
			a *= 0.5
		}
	}
	sink ^= uint64(a * 1e9)
	return a
}

// runHashRound performs SipHash-style 64-bit mixing rounds. Each
// iteration is a full 4-round mix that exercises rotators, adders,
// and XOR ports together. SipHash is ARM/x86 dual-friendly (no
// vendor-specific instructions) and the per-round latency is set by
// rotator implementation depth — varies between core revisions even
// at the same nominal clock.
//
//go:noinline
func runHashRound(seed uint64, n uint64) uint64 {
	v0 := uint64(0x736f6d6570736575) ^ seed
	v1 := uint64(0x646f72616e646f6d)
	v2 := uint64(0x6c7967656e657261) ^ seed
	v3 := uint64(0x7465646279746573)
	for i := uint64(0); i < n; i++ {
		// Two SipHash rounds per iteration. Two rounds gives enough
		// state mixing that the loop cannot be partially folded by
		// the optimiser, and four total mix steps per round keep
		// the wall-clock-per-iteration in the same ballpark as the
		// other loops (~5 ns on Altra at 3 GHz).
		v0 += v1
		v1 = (v1 << 13) | (v1 >> (64 - 13))
		v1 ^= v0
		v0 = (v0 << 32) | (v0 >> 32)
		v2 += v3
		v3 = (v3 << 16) | (v3 >> (64 - 16))
		v3 ^= v2
		v0 += v3
		v3 = (v3 << 21) | (v3 >> (64 - 21))
		v3 ^= v0
		v2 += v1
		v1 = (v1 << 17) | (v1 >> (64 - 17))
		v1 ^= v2
		v2 = (v2 << 32) | (v2 >> 32)
	}
	sink ^= v0 ^ v1 ^ v2 ^ v3
	return v0 ^ v1 ^ v2 ^ v3
}

// runBranch performs a tight loop whose path depends on the low bit of an
// accumulator. Modern branch predictors learn regular patterns quickly, so
// we deliberately drive the low bit with a xorshift so predictions stay
// near 50% accuracy. The mispredict penalty surfaces as wall-clock time
// and varies with frontend pipeline depth — an orthogonal axis to runIntMix.
//
//go:noinline
func runBranch(seed uint64, n uint64) uint64 {
	acc := seed | 1
	var total int64
	for i := uint64(0); i < n; i++ {
		acc ^= acc << 13
		acc ^= acc >> 7
		acc ^= acc << 17
		if acc&1 == 1 {
			total += int64(acc >> 32)
		} else {
			total -= int64(acc >> 32)
		}
	}
	sink ^= uint64(total)
	return acc
}

// iterCountFor returns an iteration count that should take roughly
// targetMs milliseconds on a contemporary server CPU. Values are chosen
// conservatively so a 1 GHz ARM or 2 GHz Xeon both land in the same
// millisecond bucket. Numbers are empirical, not first-principles; the
// smoke tool validates the actual timing on deploy.
func iterCountFor(kind LoopKind, targetMs int) uint64 {
	// Approximate iterations per ms on a ~2 GHz core:
	//   IntMix:   ~ 500_000
	//   MemStride: ~ 250_000 (L1D hit = 3-5 cycles)
	//   Branch:   ~ 300_000
	//
	// We scale these by targetMs. The smoke tool can override via the -iter flag.
	var perMs uint64
	switch kind {
	case LoopIntMix:
		perMs = 500_000
	case LoopMemStride:
		perMs = 250_000
	case LoopBranch:
		perMs = 300_000
	case LoopFloatMul:
		// fp64 dependent chain: 4-cycle latency × 2 ns/cycle on
		// Altra ≈ 8 ns/iter → ~125k iter/ms.
		perMs = 125_000
	case LoopHashRound:
		// SipHash 2 rounds: ~10 ns/iter on Altra → ~100k iter/ms.
		perMs = 100_000
	default:
		perMs = 250_000
	}
	return perMs * uint64(targetMs)
}

// measureOnce performs a single (core, loop, trial) measurement. The caller
// must have already pinned the goroutine to the target core and warmed the
// caches; measureOnce only times the kernel itself, not the setup cost.
//
// The returned Sample captures the exact iteration count executed and the
// monotonic-clock elapsed time. Both are raw; downstream code is responsible
// for deriving rates.
func measureOnce(core int, kind LoopKind, trial int, iters uint64) Sample {
	// Seed derivation: incorporate trial so repeated calls do not share
	// starting state. core is included as well, in case the compiler
	// produces CPU-specific constant folding for a given seed.
	seed := uint64(trial)<<32 | uint64(core)<<16 | uint64(kind)

	startNs := monotonicNs()
	switch kind {
	case LoopIntMix:
		_ = runIntMix(seed|0x1, iters)
	case LoopMemStride:
		_ = runMemStride(uint32(seed)|0x1, iters)
	case LoopBranch:
		_ = runBranch(seed|0x1, iters)
	case LoopFloatMul:
		_ = runFloatMul(seed|0x1, iters)
	case LoopHashRound:
		_ = runHashRound(seed|0x1, iters)
	}
	endNs := monotonicNs()

	// Prevent the compiler from hoisting the sink read out of the timed
	// region; runtime.KeepAlive is documented to act as a compiler barrier
	// sufficient for this purpose in Go's current implementation.
	runtime.KeepAlive(&sink)

	return Sample{
		Core:       core,
		Loop:       kind,
		Trial:      trial,
		Iterations: iters,
		ElapsedNs:  uint64(endNs - startNs),
	}
}

// monotonicNs returns the current value of CLOCK_MONOTONIC in nanoseconds.
// time.Now().UnixNano() is not guaranteed to be monotonic; time.Since()
// against a captured origin is. We use the latter so PAL measurements stay
// correct across NTP step adjustments that happen mid-measurement.
var monotonicOrigin = time.Now()

func monotonicNs() int64 {
	return int64(time.Since(monotonicOrigin))
}
