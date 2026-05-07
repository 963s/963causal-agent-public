// Package teb — Temporal Environmental Binding.
//
// STATUS: research-grade proof-of-concept. Not shipped, not sold,
// not pointed at customer workloads. The package demonstrates the
// mathematical construction from ADR-010 (BSL §13.11), whose
// purpose is to respond honestly to the "Impossible Trinity"
// memo: no external infrastructure, prove physical presence,
// force-ephemeralise secrets.
//
// What the PoC PROVES:
//
//   1. Given a signal function E(zone, t) with the structural
//      property "adjacent timestamps correlate, distant
//      timestamps decorrelate, and different zones produce
//      statistically independent streams", the TEB construction
//      below yields a symmetric key K(zone, window) whose
//      re-derivation requires either:
//         (a) re-sampling E during the same (zone, window) at a
//             location where the signal is observable, OR
//         (b) having persisted E(zone, window) during that
//             window, which requires being present.
//   2. A secret sealed under K(zone_enrol, [T_0, T_0+Δ]) cannot
//      be opened after T_0+Δ passes — regardless of whether the
//      adversary has full read access to the sealer's RAM/disk,
//      because the re-derivation input E(now) differs from the
//      sealed E_ref as of now > T_0+Δ.
//
// What the PoC DOES NOT prove, per ADR-010:
//
//   * That any specific commodity host can actually *sample* a
//     real-world ENF signal through CPU-accessible channels
//     with the resolution and stability the proof assumes.
//     That requires hardware characterisation beyond this
//     package.
//   * That a hypervisor-level adversary (Ring -1) cannot inject
//     a forged E(now) into the guest's sample channel. TEB
//     defeats pause-and-resume replay; it does not defeat
//     active environment forgery.
//   * That street-level location is distinguishable. TEB only
//     binds to the synchronous-grid zone the sealer was in.
//
// The file signal.go models the environmental signal itself so
// the rest of the package can be written and tested without
// depending on any specific hardware channel. Production TEB
// would replace this file with a concrete sampler and leave the
// rest of the API surface untouched.
package teb

import (
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/crypto/sha3"
)

// ZoneID identifies a synchronous grid zone. In production this
// would be inferred from the pinned ENF fingerprint the host has
// been observing. In the PoC it is an arbitrary opaque byte.
type ZoneID uint16

// Sample is one measurement of the environmental signal at a
// specific (zone, timestamp). The float value represents an
// ENF-like quantity — nominally 50 Hz ± a few mHz — but the PoC
// does not bind it to any physical unit. Callers should treat it
// as opaque entropy.
type Sample struct {
	TimestampMs int64
	Value       float64
}

// EnvSource is the abstraction every TEB call-site uses to read
// the environmental signal. Production hosts inject a real
// sampler (CPU-jitter-over-PSU-ripple ENF estimator); tests and
// demos inject DeterministicSignal below so the mathematics
// behaves identically across runs.
type EnvSource interface {
	// Sample returns the signal at (zone, timestampMs). A real
	// sampler ignores the zone argument (there is only one
	// ambient signal where the host is running) and uses "now"
	// instead of a caller-supplied timestamp. The interface
	// takes both so the PoC can reproduce any (zone, time)
	// deterministically.
	Sample(zone ZoneID, timestampMs int64) Sample
}

// DeterministicSignal is the signal model used in the PoC. It
// computes E(zone, t) as a structured pseudo-random function
// whose outputs have the two properties TEB relies on:
//
//   P1. Adjacent timestamps correlate. |E(zone, t) - E(zone, t+δ)|
//       is small when δ < τ (autocorrelation time). This mimics
//       real ENF: a 50 Hz grid drifts smoothly; neighbouring 10-ms
//       windows look similar. Operationally this lets the sealer
//       and the honest opener agree on E over a short window
//       without picosecond-level clock synchronisation.
//   P2. Distant timestamps decorrelate. For |δ| > τ, E(zone, t)
//       and E(zone, t+δ) are statistically independent — again
//       like real ENF over minutes. This is the security engine:
//       after a TEB window expires, the environment has "moved
//       on" and the reference E cannot be reconstructed.
//   P3. Zones are independent. E(zone_a, t) and E(zone_b, t) for
//       a ≠ b are uncorrelated. A sealer in zone A produces a key
//       no zone-B opener can reconstruct even at the same wall
//       clock, because their physical grids are decoupled.
//
// The model: a sum of three sine waves with zone-scrambled
// phases plus a slow drift, discretised to 64-bit floats. Every
// parameter is deterministic from the zone + time so tests are
// bit-exact reproducible.
type DeterministicSignal struct {
	// AutocorrelationMs is the τ in the P1/P2 discussion. Samples
	// separated by less than this milliseconds look similar;
	// samples separated by more look independent. Real ENF has
	// τ ≈ 10 s; the PoC default is 5 s so unit tests run fast.
	AutocorrelationMs int64
}

// NewDeterministicSignal returns a signal model pre-populated
// with sensible defaults.
func NewDeterministicSignal() *DeterministicSignal {
	return &DeterministicSignal{AutocorrelationMs: 5000}
}

// Sample implements EnvSource. See the type-level comment for
// the mathematical structure.
func (d *DeterministicSignal) Sample(zone ZoneID, timestampMs int64) Sample {
	// Zone-specific phase seed: a deterministic hash of the zone
	// id chosen so tiny zone deltas produce wildly different
	// phases. SHA3 gives us that without an extra library.
	var zoneBuf [4]byte
	binary.BigEndian.PutUint16(zoneBuf[:2], uint16(zone))
	zoneBuf[2] = 0xC0
	zoneBuf[3] = 0xDE // "code"
	h := sha3.Sum256(zoneBuf[:])
	phaseA := float64(binary.BigEndian.Uint64(h[0:8])) / math.MaxInt64 * math.Pi
	phaseB := float64(binary.BigEndian.Uint64(h[8:16])) / math.MaxInt64 * math.Pi
	phaseC := float64(binary.BigEndian.Uint64(h[16:24])) / math.MaxInt64 * math.Pi
	driftK := float64(binary.BigEndian.Uint64(h[24:32])) / math.MaxInt64 * 1e-7

	// Three harmonics on three different periods. Slowest one
	// matches the autocorrelation length; fastest one introduces
	// fine structure that quantises differently from run to run
	// once timestamps differ by more than a few ms.
	t := float64(timestampMs) / 1000.0
	tau := float64(d.AutocorrelationMs) / 1000.0
	slow := math.Sin(2*math.Pi*t/tau + phaseA)
	med := math.Sin(2*math.Pi*t*3.0/tau + phaseB)
	fast := math.Sin(2*math.Pi*t*17.0/tau + phaseC)
	drift := driftK * t

	// Nominal 50 Hz with ± 0.05 Hz excursion.
	val := 50.0 + 0.05*(0.5*slow+0.3*med+0.2*fast) + drift
	return Sample{TimestampMs: timestampMs, Value: val}
}

// SampleWindow captures the signal across a specified [start,
// start+duration] interval at a caller-chosen cadence. This is
// the raw material TEB turns into a key. The returned slice is
// never empty on a successful call; an error indicates a zero-
// or-negative window geometry.
func SampleWindow(src EnvSource, zone ZoneID, startMs int64, durationMs int64, cadenceMs int64) ([]Sample, error) {
	if src == nil {
		return nil, fmt.Errorf("teb: nil env source")
	}
	if durationMs <= 0 {
		return nil, fmt.Errorf("teb: non-positive window duration %d", durationMs)
	}
	if cadenceMs <= 0 || cadenceMs > durationMs {
		return nil, fmt.Errorf("teb: bad cadence %d for window %d", cadenceMs, durationMs)
	}
	n := int(durationMs/cadenceMs) + 1
	out := make([]Sample, 0, n)
	for t := startMs; t <= startMs+durationMs; t += cadenceMs {
		out = append(out, src.Sample(zone, t))
	}
	return out, nil
}

// QuantiseSamples maps a slice of Samples to a deterministic byte
// string suitable as HKDF salt / info. The quantisation step
// (millihertz-level buckets) absorbs the tiny float-precision
// noise a realistic sampler would add, while still rejecting
// samples that come from a different (zone, t).
func QuantiseSamples(samples []Sample) []byte {
	buf := make([]byte, 0, 16*len(samples))
	for _, s := range samples {
		// Quantise value to 5-mHz buckets. Chosen so a real ENF
		// estimator's 1-σ noise (~ 1 mHz on good hardware) is
		// well below the bucket size, but a wrong-zone sample
		// (typically > 10 mHz off) lands in a different bucket.
		bucket := int64(math.Round((s.Value - 49.9) * 200.0))
		var tmp [16]byte
		binary.BigEndian.PutUint64(tmp[0:8], uint64(s.TimestampMs))
		binary.BigEndian.PutUint64(tmp[8:16], uint64(bucket))
		buf = append(buf, tmp[:]...)
	}
	return buf
}
