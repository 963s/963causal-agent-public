// Command mstc-smoke is a standalone smoke test for the W3 physics probes.
// It exercises MSTC and External Witness, prints their digests, and exits.
// Useful for CI and for verifying the probes on a new host without
// requiring an enrolled server connection.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/963causal/agent/internal/probe"
)

func main() {
	fmt.Println("=== 963causal W3 Physics Layer smoke test ===")
	fmt.Printf("arch=%s\n", probe.ArchName)

	// --- MSTC ---
	fmt.Println("\n[MSTC] sampling 2048 measurements (warmup 64)...")
	start := time.Now()
	mstc := probe.SampleMSTC()
	fmt.Printf("  elapsed         = %s\n", time.Since(start).Round(time.Microsecond))
	fmt.Printf("  hw_hz           = %d (%.3f MHz)\n", mstc.HwHz, float64(mstc.HwHz)/1e6)
	fmt.Printf("  samples kept    = %d\n", mstc.SampleCount)
	fmt.Println("  pairwise ratios (expected near 1.0 on bare metal):")
	fmt.Printf("    HW / VDSO         = %.9f  σ=%.3e\n", mstc.RatioHwVdsoMean, mstc.RatioHwVdsoStddev)
	fmt.Printf("    VDSO / SYSCALL    = %.9f  σ=%.3e\n", mstc.RatioVdsoSyscallMean, mstc.RatioVdsoSyscallStddev)
	fmt.Printf("    HW / HW_ALT       = %.9f  σ=%.3e\n", mstc.RatioHwHw2Mean, mstc.RatioHwHw2Stddev)
	fmt.Println("  read-latency (p50 / p99, nanoseconds):")
	fmt.Printf("    HW      : %7.1f / %7.1f\n", mstc.HwReadP50Ns, mstc.HwReadP99Ns)
	fmt.Printf("    VDSO    : %7.1f / %7.1f\n", mstc.VdsoReadP50Ns, mstc.VdsoReadP99Ns)
	fmt.Printf("    SYSCALL : %7.1f / %7.1f\n", mstc.SyscallReadP50Ns, mstc.SyscallReadP99Ns)

	// --- External Witness ---
	fmt.Println("\n[Witness] fetching drand beacon round...")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start = time.Now()
	w := probe.SampleExternalWitness(ctx)
	fmt.Printf("  elapsed = %s\n", time.Since(start).Round(time.Millisecond))
	if w == nil {
		fmt.Println("  (no witness — all relays unreachable or blocked)")
		os.Exit(0)
	}
	fmt.Printf("  chain   = %s\n", w.ChainHash)
	fmt.Printf("  round   = %d\n", w.Round)
	fmt.Printf("  rand    = %s\n", hex.EncodeToString(w.Randomness))
	fmt.Printf("  sig     = %s... (%d bytes)\n",
		hex.EncodeToString(w.Signature[:16]), len(w.Signature))
	if w.RoundTimeUnix != 0 {
		ageMs := w.CapturedAtMs - w.RoundTimeUnix*1000
		fmt.Printf("  age     = %d ms (captured after round draw)\n", ageMs)
	}
}
