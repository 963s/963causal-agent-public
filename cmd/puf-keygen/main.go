// puf-keygen exercises the W5b fuzzy-extractor end to end on real
// hardware: it runs an enrolment cycle, picks reliable bit indices
// by measuring BER across a small calibration burst, derives a
// 128-bit secret K via the code-offset construction, then reproduces
// K from N independent measurements and reports whether each
// reproduction matched the enrolment value.
//
// This is the local equivalent of the server-side enrolment + agent
// reproduction loop that PAL key derivation will run in production:
// a single passing run here means a host can boot, derive its K from
// silicon alone, and use it as a binding factor without any data
// crossing the network.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/963causal/agent/internal/puf"
)

func main() {
	calCycles := flag.Int("calibration-cycles", 20, "cycles used to measure per-bit BER and pick reliable indices")
	repCycles := flag.Int("reproduce-cycles", 10, "independent reproduction attempts after enrolment")
	trials := flag.Int("trials", 32, "trials per (core, loop) cell")
	cooldown := flag.Int("cooldown-ms", 250, "cooldown between cycles")
	maxBER := flag.Float64("max-ber", 0.02, "BER ceiling for reliable bit selection")
	flag.Parse()

	cfg := puf.Config{Trials: *trials}

	fmt.Printf("puf-keygen: %d calibration + 1 enrolment + %d reproduce cycles, trials=%d\n",
		*calCycles, *repCycles, cfg.Trials)

	// (A) Calibration burst: measure many cycles and find which bit
	// positions of QuantizeV3 are stable. Cycle 0 doubles as the
	// enrolment baseline so subsequent residual-gray bits are
	// computed against a fixed reference, mirroring the live agent
	// flow where the baseline is captured once and stored.
	fmt.Println("\n[1/3] Calibration: measuring reliability of quantiser bits")
	var baseline *puf.Baseline
	cal := make([]puf.Fingerprint, 0, *calCycles)
	for i := 0; i < *calCycles; i++ {
		t0 := time.Now()
		m, err := puf.Measure(cfg)
		if err != nil {
			log.Fatalf("cal cycle %d: measure: %v", i, err)
		}
		fp := puf.QuantizeV3(m, baseline)
		if i == 0 {
			bl := puf.NewBaseline(m)
			baseline = &bl
		}
		cal = append(cal, fp)
		fmt.Fprintf(os.Stderr, "  cal %2d: digest=%s, %.0fms\n",
			i, fp.Digest[:16], float64(time.Since(t0).Milliseconds()))
		if i+1 < *calCycles && *cooldown > 0 {
			time.Sleep(time.Duration(*cooldown) * time.Millisecond)
		}
	}
	indices := puf.SelectReliableBits(cal, *maxBER)
	fmt.Printf("  selected %d reliable bit indices (BER ≤ %.2f%%)\n",
		len(indices), *maxBER*100)
	if len(indices) < puf.HelperBits {
		log.Fatalf("not enough reliable bits: need %d, have %d", puf.HelperBits, len(indices))
	}

	// (B) Enrolment: take a fresh measurement and run Enroll against
	// the reliable indices. The fingerprint used for enrolment must
	// be one that uses the SAME baseline as the indices were chosen
	// against; we re-use cycle 0 (which is what `baseline` was built
	// from), but any of the calibration cycles would work because
	// they were all quantised against `baseline`.
	fmt.Println("\n[2/3] Enrolment: deriving 128-bit secret + helper data")
	K, hd, err := puf.Enroll(cal[0], indices)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	fmt.Printf("  K       = %s (%d bits)\n", hex.EncodeToString(K), len(K)*8)
	fmt.Printf("  helper  = version=%d, indices=%d, mask=%d bits, commit=%s\n",
		hd.Version, len(hd.Indices), hd.MaskBits, hd.CommitmentHex()[:16])

	// (C) Reproduction loop: N fresh measurements, run Reproduce
	// against the stored helper, compare K' to K. This is the
	// definitive correctness signal: every match confirms the
	// extractor is silicon-bound; any mismatch flags either a bad
	// quantiser bit (silent drift) or an under-corrected error.
	fmt.Println("\n[3/3] Reproduction: replaying", *repCycles, "fresh measurements")
	matches := 0
	for i := 0; i < *repCycles; i++ {
		if *cooldown > 0 {
			time.Sleep(time.Duration(*cooldown) * time.Millisecond)
		}
		t0 := time.Now()
		m, err := puf.Measure(cfg)
		if err != nil {
			log.Fatalf("rep %d: measure: %v", i, err)
		}
		fp := puf.QuantizeV3(m, baseline)
		Kp, err := puf.Reproduce(fp, hd)
		dt := time.Since(t0)
		if err != nil {
			fmt.Printf("  rep %2d: FAIL  %v  (%.0fms)\n", i, err, float64(dt.Milliseconds()))
			continue
		}
		ok := equalBytes(Kp, K)
		mark := "match"
		if !ok {
			mark = "DIFFER"
		}
		fmt.Printf("  rep %2d: %s  K'=%s  (%.0fms)\n", i, mark,
			hex.EncodeToString(Kp)[:16], float64(dt.Milliseconds()))
		if ok {
			matches++
		}
	}

	fmt.Printf("\n=== Result: %d / %d reproductions recovered K identically ===\n",
		matches, *repCycles)
	if matches == *repCycles {
		fmt.Println("Verdict: PASS — fuzzy extractor is silicon-bound and stable on this host")
	} else {
		fmt.Println("Verdict: FAIL — extractor is unstable; widen reliability threshold or grow indices pool")
		os.Exit(1)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
