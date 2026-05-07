// puf-ber characterises the per-bit error rate of the PUF fingerprint
// quantiser on the host it runs on. It exists because we cannot pick a
// fuzzy-extractor ECC sensibly without knowing the actual bit-error
// distribution: the textbook "BER ≈ 5%" assumption that dominates the
// PUF literature comes from purpose-built ring-oscillator silicon, not
// from cloud VMs with homogenised cores.
//
// Methodology:
//
//   1. Take N back-to-back measurements with the same Config the agent
//      uses for attestation. Cycle 0 is the reference ("enrollment").
//   2. Quantise each cycle with the production Quantize().
//   3. For each bit position i, record how many of the N-1 follow-up
//      cycles flipped that bit relative to cycle 0. BER[i] = flips / (N-1).
//   4. Bucket the BERs and print a histogram, plus the count of bits
//      that fall below sensible ECC-friendly thresholds (1%, 5%, 10%).
//
// The output is intentionally human-readable rather than JSON: this is a
// diagnostic that an operator runs once per host class (ARM Altra, x86
// Cascade Lake, bare-metal Ryzen, ...) to choose ECC parameters; the
// numbers don't need to be machine-consumed.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/963causal/agent/internal/puf"
)

func main() {
	cycles := flag.Int("cycles", 30, "number of measurement cycles to run (cycle 0 is the reference)")
	trials := flag.Int("trials", 32, "trials per (core, loop) cell")
	cooldownMs := flag.Int("cooldown-ms", 250, "wall-clock cooldown between cycles to let DVFS settle")
	verbose := flag.Bool("verbose", false, "print per-bit BER vector")
	scheme := flag.String("scheme", "v1", "quantiser to test: v1, v2, or v3")
	maxBER := flag.Float64("max-ber", 0.02, "BER ceiling for reliability-based bit selection report")
	flag.Parse()

	if *cycles < 5 {
		log.Fatalf("need at least 5 cycles to estimate BER (--cycles)")
	}
	if !puf.Supported() {
		log.Fatalf("puf measurement unsupported on this platform")
	}

	cfg := puf.Config{
		Trials:       *trials,
		WarmupTrials: puf.DefaultWarmupTrials,
		TargetLoopMs: puf.DefaultTargetLoopMs,
	}

	fmt.Fprintf(os.Stderr, "puf-ber: running %d cycles × %d trials (scheme=%s)...\n",
		*cycles, *trials, *scheme)

	// V2 needs the cycle-0 baseline to compute the residual gray-code
	// bits. Cycle 0 itself is quantised against a nil baseline (which
	// the residual code interprets as "I'm the reference, residual is
	// zero"), so subsequent cycles get measured against cycle-0's
	// per-cell median + MAD. This mirrors the live agent flow:
	// enrolment → store baseline → reproduce vs. baseline.
	var baseline *puf.Baseline
	fps := make([]puf.Fingerprint, 0, *cycles)
	totalStart := time.Now()
	for i := 0; i < *cycles; i++ {
		t0 := time.Now()
		m, err := puf.Measure(cfg)
		if err != nil {
			log.Fatalf("cycle %d: measure: %v", i, err)
		}
		var fp puf.Fingerprint
		switch *scheme {
		case "v1":
			fp = puf.Quantize(m)
		case "v2":
			fp = puf.QuantizeV2(m, baseline)
			if i == 0 {
				bl := puf.NewBaseline(m)
				baseline = &bl
			}
		case "v3":
			fp = puf.QuantizeV3(m, baseline)
			if i == 0 {
				bl := puf.NewBaseline(m)
				baseline = &bl
			}
		default:
			log.Fatalf("unknown scheme %q (want v1, v2, or v3)", *scheme)
		}
		fps = append(fps, fp)
		fmt.Fprintf(os.Stderr, "  cycle %2d: %d bits, digest=%s, %.0fms\n",
			i, fp.Length, fp.Digest[:16], float64(time.Since(t0).Milliseconds()))
		if i+1 < *cycles && *cooldownMs > 0 {
			time.Sleep(time.Duration(*cooldownMs) * time.Millisecond)
		}
	}
	fmt.Fprintf(os.Stderr, "puf-ber: %d cycles in %.1fs total\n",
		*cycles, time.Since(totalStart).Seconds())

	// Sanity check: every cycle must have produced the same bit length
	// (different lengths would mean the quantiser changed shape between
	// cycles, which would invalidate the comparison).
	bitLen := fps[0].Length
	for i, fp := range fps {
		if fp.Length != bitLen {
			log.Fatalf("cycle %d emitted %d bits, expected %d", i, fp.Length, bitLen)
		}
	}

	// Per-bit flip count: each follow-up cycle (1..N-1) is XOR'd against
	// the reference cycle 0, and we accumulate flips per bit position.
	flips := make([]int, bitLen)
	for c := 1; c < len(fps); c++ {
		for b := 0; b < bitLen; b++ {
			if bitAt(fps[0].Bits, b) != bitAt(fps[c].Bits, b) {
				flips[b]++
			}
		}
	}
	denom := float64(len(fps) - 1)
	ber := make([]float64, bitLen)
	for i, f := range flips {
		ber[i] = float64(f) / denom
	}

	// Aggregate stats.
	var sum, mx float64
	for _, b := range ber {
		sum += b
		if b > mx {
			mx = b
		}
	}
	mean := sum / float64(bitLen)

	// Bucket counts for ECC budgeting. Stable bits (BER == 0) are the
	// only ones that contribute "free" entropy; everything else costs
	// ECC redundancy proportional to its error rate.
	buckets := []struct {
		max   float64
		label string
	}{
		{0.0001, "stable      (BER = 0%)"},
		{0.01, "near-stable (BER ≤ 1%)"},
		{0.05, "low-noise   (BER ≤ 5%)"},
		{0.10, "medium      (BER ≤ 10%)"},
		{0.25, "noisy       (BER ≤ 25%)"},
		{0.49, "very noisy  (BER ≤ 49%)"},
		{1.01, "random      (BER ≈ 50%)"},
	}
	counts := make([]int, len(buckets))
	for _, b := range ber {
		for i, bk := range buckets {
			if b <= bk.max {
				counts[i]++
				break
			}
		}
	}

	fmt.Println()
	fmt.Println("=== Per-bit BER summary ===")
	fmt.Printf("Total bits:         %d\n", bitLen)
	fmt.Printf("Reference cycles:   %d follow-up vs cycle 0\n", len(fps)-1)
	fmt.Printf("Mean BER:           %.4f  (%.2f%%)\n", mean, mean*100)
	fmt.Printf("Max  BER:           %.4f  (%.2f%%)\n", mx, mx*100)
	fmt.Println()
	fmt.Println("=== Distribution ===")
	for i, bk := range buckets {
		bar := ""
		if counts[i] > 0 {
			bar = bars(counts[i], bitLen)
		}
		fmt.Printf("  %-26s %4d (%5.1f%%) %s\n", bk.label, counts[i],
			100*float64(counts[i])/float64(bitLen), bar)
	}

	// ECC sizing helper: count how many bits we have at each stability
	// threshold so the operator can read off a workable (k, n, t) for
	// a code-offset construction. We assume we keep only bits with
	// BER ≤ threshold; the per-bit BER inside that pool is bounded by
	// the threshold, so a t-error-correcting code with t ≥ ⌈threshold·n⌉
	// + safety margin is the rough sizing target.
	fmt.Println()
	fmt.Println("=== ECC sizing candidates (128-bit key target) ===")
	for _, threshold := range []float64{0.01, 0.05, 0.10} {
		var n int
		for _, b := range ber {
			if b <= threshold {
				n++
			}
		}
		// Reed-Muller(1, m) corrects up to 2^(m-2)-1 errors in 2^m bits.
		// We just report the raw n and the worst-case errors so the
		// operator can pick a code by inspection rather than us
		// pretending we already know which one.
		expectedErrs := threshold * float64(n)
		fmt.Printf("  BER ≤ %4.1f%%:  n = %3d stable bits, expected errors per reproduce ≈ %.1f\n",
			threshold*100, n, expectedErrs)
	}

	// Per-group BER. V1 emits four groups; V2 prepends those plus
	// three new sources (residual-gray, sub-window, ratio-gray). The
	// group boundaries are derived from the fingerprint geometry so
	// adding a new core/loop never breaks the slicing.
	fp := fps[0]
	pair := fp.Cores * (fp.Cores - 1) / 2 * fp.Loops
	perCore := fp.Cores * fp.Loops
	cvQ := fp.Cores * fp.Loops * 2
	pairMag := pair

	type group struct {
		name     string
		from, to int
	}
	groups := []group{
		{"pair-sign      ", 0, pair},
		{"per-core-vs-med", pair, pair + perCore},
		{"cv-quartile    ", pair + perCore, pair + perCore + cvQ},
		{"pair-magnitude ", pair + perCore + cvQ, pair + perCore + cvQ + pairMag},
	}
	if *scheme == "v2" {
		v1End := pair + perCore + cvQ + pairMag
		residGray := fp.Cores * fp.Loops * 3
		subWin := fp.Cores * fp.Loops * 4
		ratioGray := 3 * fp.Cores * 3
		groups = append(groups,
			group{"residual-gray  ", v1End, v1End + residGray},
			group{"sub-window     ", v1End + residGray, v1End + residGray + subWin},
			group{"ratio-gray     ", v1End + residGray + subWin, v1End + residGray + subWin + ratioGray},
		)
	}
	if *scheme == "v3" {
		// V3 layout depends on actual loop count (3 in W5b initial,
		// 5 once V4 loop kinds are enabled). Compute boundaries from
		// the live fingerprint geometry rather than hard-coding.
		residGray := fp.Cores * fp.Loops * 3
		loopPairs := fp.Loops * (fp.Loops - 1) / 2
		ratioGray := loopPairs * fp.Cores * 3
		crossCore := fp.Loops * (fp.Cores * (fp.Cores - 1) / 2) * 3
		magGray := fp.Cores * fp.Loops * 3
		cvGray := fp.Cores * fp.Loops * 3
		off := 0
		groups = []group{{"residual-gray  ", off, off + residGray}}
		off += residGray
		groups = append(groups, group{"loop-ratio-gray", off, off + ratioGray})
		off += ratioGray
		groups = append(groups, group{"core-ratio-gray", off, off + crossCore})
		off += crossCore
		groups = append(groups, group{"magnitude-gray ", off, off + magGray})
		off += magGray
		groups = append(groups, group{"cv-gray        ", off, off + cvGray})
	}

	fmt.Println()
	fmt.Println("=== BER by quantiser group ===")
	for _, g := range groups {
		if g.to > bitLen {
			g.to = bitLen
		}
		if g.from >= g.to {
			continue
		}
		var s float64
		var stableInGroup int
		for i := g.from; i < g.to; i++ {
			s += ber[i]
			if ber[i] <= *maxBER {
				stableInGroup++
			}
		}
		fmt.Printf("  %s [%3d..%3d]  mean BER = %5.2f%%  reliable@%.0f%% = %d/%d\n",
			g.name, g.from, g.to-1, 100*s/float64(g.to-g.from),
			*maxBER*100, stableInGroup, g.to-g.from)
	}

	// Reliability-based bit-selection report. This is the actual
	// question fuzzy-extractor sizing depends on: how many bit
	// positions are reliable enough to treat as "input alphabet" and
	// what is the residual BER inside that pool.
	reliable := puf.SelectReliableBits(fps, *maxBER)
	if len(reliable) > 0 {
		var sumIn, maxIn float64
		for _, idx := range reliable {
			sumIn += ber[idx]
			if ber[idx] > maxIn {
				maxIn = ber[idx]
			}
		}
		meanIn := sumIn / float64(len(reliable))
		fmt.Println()
		fmt.Println("=== Reliability-based bit selection ===")
		fmt.Printf("  Threshold:           BER ≤ %.2f%%\n", *maxBER*100)
		fmt.Printf("  Selected bits:       %d / %d\n", len(reliable), bitLen)
		fmt.Printf("  Mean BER (selected): %.4f  (%.2f%%)\n", meanIn, meanIn*100)
		fmt.Printf("  Max  BER (selected): %.4f  (%.2f%%)\n", maxIn, maxIn*100)
		// 128-bit key feasibility: we need n stable bits and a code
		// that corrects t = ⌈max_ber × n⌉ errors with safety margin.
		// BCH(127, 64, 5) corrects up to 10 errors in 127 bits (4
		// errors carries the worst-case 3% rate × 127 = 3.8 errors
		// with margin). Two parallel BCH(127, 64) blocks → 128 bit
		// key from 254 PUF bits.
		fmt.Println()
		fmt.Println("=== 128-bit key feasibility (BCH-based) ===")
		fmt.Printf("  Blocks needed (BCH(127,64,t)): 2  →  254 PUF bits required\n")
		fmt.Printf("  Available in pool:             %d\n", len(reliable))
		switch {
		case len(reliable) >= 254:
			fmt.Printf("  Verdict:  feasible — pool covers two full BCH blocks\n")
		case len(reliable) >= 127:
			fmt.Printf("  Verdict:  64-bit key feasible — single BCH(127,64,t) block\n")
		default:
			fmt.Printf("  Verdict:  insufficient bits even for a 64-bit key — quantiser needs more sources\n")
		}
	}

	if *verbose {
		fmt.Println()
		fmt.Println("=== Per-bit BER (sorted ascending) ===")
		idx := make([]int, bitLen)
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return ber[idx[a]] < ber[idx[b]] })
		for _, i := range idx {
			fmt.Printf("  bit %3d  BER = %5.2f%%  flips = %d/%d\n",
				i, 100*ber[i], flips[i], len(fps)-1)
		}
	}
}

// bitAt returns bit position b from a little-endian packed byte slice.
// The packing matches puf.bitBuilder so the decoded bit order is the
// same as the order the quantiser appended them in.
func bitAt(buf []byte, b int) int {
	if b>>3 >= len(buf) {
		return 0
	}
	return int((buf[b>>3] >> uint(b&7)) & 1)
}

// bars renders a fixed-width visual indicator for a bucket count.
// 40 columns is enough resolution for 72-bit fingerprints without
// taking over the terminal.
func bars(count, total int) string {
	const width = 40
	n := count * width / total
	if n == 0 && count > 0 {
		n = 1
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = '#'
	}
	return string(out)
}
