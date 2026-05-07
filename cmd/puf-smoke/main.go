// Command puf-smoke drives the PUF measurement layer end-to-end on the
// local host and prints a human-readable report. Its purpose is to catch
// measurement regressions and tune parameters before wiring PAL into the
// main agent loop; it is not a production tool and intentionally does no
// server round-trip.
//
// The tool takes the first cycle as an "enrollment" and every subsequent
// cycle as an "attestation" against that baseline, so the operator can see
// what the server would see in production steady state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/963causal/agent/internal/puf"
)

func main() {
	trials := flag.Int("trials", puf.DefaultTrials, "scored trials per (core,loop) cell")
	warmup := flag.Int("warmup", puf.DefaultWarmupTrials, "warmup trials per cell")
	loopMs := flag.Int("loop-ms", puf.DefaultTargetLoopMs, "target wall-clock ms per loop")
	cycles := flag.Int("cycles", 3, "total measurement cycles (first is enrolment)")
	verbose := flag.Bool("verbose", false, "dump per-core-loop baseline and each cycle's medians")
	dumpJSON := flag.Bool("json", false, "append JSON baseline + reports to stdout after report")
	flag.Parse()

	log.SetFlags(0)

	if runtime.GOOS != "linux" {
		log.Fatalf("puf-smoke: requires Linux (got %s)", runtime.GOOS)
	}
	if runtime.NumCPU() < 2 {
		log.Fatalf("puf-smoke: need at least 2 logical CPUs")
	}
	if *cycles < 2 {
		log.Fatalf("puf-smoke: need at least 2 cycles (1 enroll + N attest)")
	}

	cfg := puf.Config{
		Trials:       *trials,
		WarmupTrials: *warmup,
		TargetLoopMs: *loopMs,
	}

	fmt.Printf("puf-smoke: arch=%s cores=%d trials=%d warmup=%d loop_ms=%d cycles=%d\n",
		runtime.GOARCH, runtime.NumCPU(), *trials, *warmup, *loopMs, *cycles)

	// --- enrollment ---
	fmt.Printf("\n[cycle 1/%d] enrolling baseline...\n", *cycles)
	m0, err := puf.Measure(cfg)
	if err != nil {
		log.Fatalf("puf-smoke: enroll Measure: %v", err)
	}
	baseline := puf.NewBaseline(m0)
	if *verbose {
		fmt.Println("  baseline medians (iters/sec, ±CV%):")
		dumpCoreStats(baseline.PerCoreLoop)
	}

	// --- attestation cycles ---
	type cycleResult struct {
		Cycle   int         `json:"cycle"`
		Report  puf.Report  `json:"report"`
		Stats   puf.Stats   `json:"-"`
	}
	var results []cycleResult
	worstVerdict := "PASS"
	for c := 2; c <= *cycles; c++ {
		fmt.Printf("\n[cycle %d/%d] attesting...\n", c, *cycles)
		m, err := puf.Measure(cfg)
		if err != nil {
			log.Fatalf("puf-smoke: attest %d Measure: %v", c, err)
		}
		cur := puf.Summarise(m)
		report, err := puf.CompareToBaseline(cur, baseline)
		if err != nil {
			log.Fatalf("puf-smoke: attest %d Compare: %v", c, err)
		}
		results = append(results, cycleResult{Cycle: c, Report: report, Stats: cur})

		fmt.Printf("  verdict=%s  max|z|=%.2f  mean|z|=%.2f  max|ratio|=%.3f%%\n",
			report.Verdict, report.MaxAbsZ, report.MeanAbsZ, report.MaxAbsRatio*100)

		if *verbose {
			fmt.Println("  per-cell drift:")
			for _, d := range report.Cells {
				fmt.Printf("    c%d %s: base=%.3em cur=%.3em  ratio=%+.3f%%  z=%+.2f\n",
					d.Core, d.Loop.String(),
					d.BaselineMedian/1e6, d.CurrentMedian/1e6,
					d.Ratio*100, d.Z)
			}
		}

		if worse(report.Verdict, worstVerdict) {
			worstVerdict = report.Verdict
		}
	}

	// --- summary ---
	fmt.Printf("\n=== summary: %d attestations, worst verdict: %s ===\n",
		len(results), worstVerdict)
	var maxZ, maxRatio float64
	var meanZSum float64
	for _, r := range results {
		if r.Report.MaxAbsZ > maxZ {
			maxZ = r.Report.MaxAbsZ
		}
		if r.Report.MaxAbsRatio > maxRatio {
			maxRatio = r.Report.MaxAbsRatio
		}
		meanZSum += r.Report.MeanAbsZ
	}
	meanZ := 0.0
	if len(results) > 0 {
		meanZ = meanZSum / float64(len(results))
	}
	fmt.Printf("max|z|        = %.2f  (PASS<=%.1f, DRIFT<=%.1f, TAMPER>=%.1f)\n",
		maxZ, puf.PassMaxZ, puf.DriftMaxZ, puf.TamperMaxZ)
	fmt.Printf("mean|z|       = %.2f  (PASS<=%.1f)\n", meanZ, puf.PassMeanZ)
	fmt.Printf("max|ratio|    = %.3f%% (DRIFT<=%.1f%%, TAMPER>=%.1f%%)\n",
		maxRatio*100, puf.DriftMaxRatio*100, puf.TamperMaxRatio*100)

	if *dumpJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		fmt.Println("\n--- baseline (JSON) ---")
		_ = enc.Encode(baseline)
		fmt.Println("--- attestation reports (JSON) ---")
		_ = enc.Encode(results)
	}

	if worstVerdict == "TAMPER" {
		fmt.Println("\nverdict: TAMPER — measurement unstable beyond tamper threshold")
		os.Exit(3)
	}
	if worstVerdict == "DRIFT" {
		fmt.Println("\nverdict: DRIFT — measurement noisy; review thresholds before enabling")
		os.Exit(2)
	}
	fmt.Println("\nverdict: PASS — baseline is stable")
}

// worse returns true if a is "worse" than b in the PASS < DRIFT < TAMPER
// ordering used by the verdict machine.
func worse(a, b string) bool {
	rank := map[string]int{"PASS": 0, "DRIFT": 1, "TAMPER": 2, "ERROR": 3}
	return rank[a] > rank[b]
}

func dumpCoreStats(cs []puf.CoreStats) {
	for _, c := range cs {
		fmt.Printf("    c%d %-3s  median=%.3em  MAD=%.3em  CV=%5.3f%%\n",
			c.Core, c.Loop.String(), c.Median/1e6, c.MAD/1e6, c.CV*100)
	}
}
