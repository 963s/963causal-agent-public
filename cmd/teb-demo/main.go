// teb-demo is the runnable demonstration of Temporal
// Environmental Binding (ADR-010). It walks through a full
// seal-then-open cycle in the happy path, then fires four
// adversarial probes that each SHOULD fail, to give a human
// auditor a visual proof of what the primitive does and does
// not guarantee.
//
// This is a SIMULATION. The environmental signal is generated
// by internal/teb.DeterministicSignal, which mathematically
// behaves like a real ENF trace (bounded autocorrelation, zone-
// independent, monotonic on long timescales) but is not
// actually sampled from any hardware. See ADR-010 §4 for the
// hardware gap this leaves open.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/963causal/agent/internal/teb"
)

func main() {
	windowStart := flag.Int64("window-start-ms", 0, "sealed-window start (logical ms)")
	windowDuration := flag.Int64("window-ms", 30000, "sealed-window duration (ms)")
	cadence := flag.Int64("cadence-ms", 100, "sampling cadence inside the window")
	zone := flag.Int("zone", 42, "zone id the sealer is bound to (0..65535)")
	flag.Parse()

	src := teb.NewDeterministicSignal()
	binding := []byte("binding-secret-from-W5b-PUF-k-pal")
	plaintext := []byte("API-key: 963causal-zero-demo-secret")

	// -------- Stage 1 : seal --------
	section("Stage 1 — Seal under zone+window binding")
	blob, err := teb.Seal(src, binding, teb.ZoneID(*zone),
		*windowStart, *windowDuration, *cadence, plaintext)
	if err != nil {
		die("seal failed: %v", err)
	}
	fmt.Printf("  plaintext: %q (%d B)\n", plaintext, len(plaintext))
	fmt.Printf("  %s\n", blob.DebugString())
	fmt.Println("  agent zeroises the derived key before returning")

	// -------- Stage 2 : honest open inside window --------
	section("Stage 2 — Honest open at t = mid-window")
	midpoint := *windowStart + *windowDuration/2
	got, err := teb.Open(src, binding, blob, teb.ZoneID(*zone), midpoint)
	if err != nil {
		die("honest open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		die("plaintext mismatch: got %q", got)
	}
	fmt.Printf("  opened at t=%d ms: %q\n", midpoint, got)

	// -------- Stage 3 : attacker snapshots + resumes late ----
	section("Stage 3 — Attacker pauses VM + resumes AFTER window expiry")
	fmt.Println("  snapshot taken at t=50 ms; VM resumes at t=window_end+10000 ms")
	resume := *windowStart + *windowDuration + 10000
	_, err = teb.Open(src, binding, blob, teb.ZoneID(*zone), resume)
	expect(err, teb.ErrOutOfWindow)

	// -------- Stage 4 : attacker tries to open from a wrong zone
	section("Stage 4 — Attacker carries the blob to a different grid zone")
	wrongZone := teb.ZoneID(*zone + 1)
	fmt.Printf("  opening from zone=%d (blob sealed under zone=%d)\n", wrongZone, *zone)
	_, err = teb.Open(src, binding, blob, wrongZone, midpoint)
	expect(err, teb.ErrWrongZone)

	// -------- Stage 5 : attacker has the blob but wrong binding
	section("Stage 5 — Attacker has the blob but different binding secret")
	_, err = teb.Open(src, []byte("not-the-real-puf-secret"), blob, teb.ZoneID(*zone), midpoint)
	expect(err, teb.ErrOpen)

	// -------- Stage 6 : attacker rewrites WindowStartMs to forge validity
	section("Stage 6 — Attacker rewrites WindowStartMs to extend validity")
	tampered := *blob
	tampered.WindowStartMs = *windowStart + 1_000_000 // pretend it was sealed later
	_, err = teb.Open(src, binding, &tampered, teb.ZoneID(*zone),
		*windowStart+1_000_000+*windowDuration/2)
	expect(err, teb.ErrOpen)

	// -------- Stage 7 : attacker feeds a forged environment --
	section("Stage 7 — Attacker feeds a forged environmental signal")
	forged := &teb.DeterministicSignal{AutocorrelationMs: 2500} // different τ
	_, err = teb.Open(forged, binding, blob, teb.ZoneID(*zone), midpoint)
	expect(err, teb.ErrOpen)

	// -------- Verdict ---------------------------------------
	section("Verdict — TEB invariants")
	fmt.Println("  ✓ honest open inside window succeeds")
	fmt.Println("  ✓ open after window expiry rejected (ErrOutOfWindow)")
	fmt.Println("  ✓ wrong-zone open rejected before AEAD tag (ErrWrongZone)")
	fmt.Println("  ✓ wrong binding secret rejected by AEAD (ErrOpen)")
	fmt.Println("  ✓ rewritten window params rejected by AEAD (ErrOpen)")
	fmt.Println("  ✓ forged environment (wrong signal model) rejected by AEAD (ErrOpen)")
	fmt.Println()
	fmt.Println("  Explicit limits (documented in ADR-010):")
	fmt.Println("    • street-level location NOT proven — only grid-zone granularity")
	fmt.Println("    • Ring -1 that can forge the SAME environmental signal the sealer")
	fmt.Println("      uses (hypervisor with access to host mains) defeats TEB")
	fmt.Println("    • real hardware ENF detection is not part of this PoC;")
	fmt.Println("      the signal here is a deterministic mathematical model")
}

// -----------------------------------------------------------------

func section(title string) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 72))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("═", 72))
}

func expect(got, want error) {
	if got == nil {
		die("expected error %v, got nil", want)
	}
	if !errors.Is(got, want) {
		die("expected error %v, got %v", want, got)
	}
	fmt.Printf("  ✓ rejected as expected: %v\n", got)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "teb-demo: "+format+"\n", args...)
	os.Exit(1)
}
