// Package puf implements a software-approximate Physical Unclonable Function
// ("ring-oscillator-style") attestation layer for the 963causal agent.
//
// MVP (W5a) scope: attestation only. We measure per-core work rates under
// several loop kernels, quantize them into a stable bit vector, and let the
// control plane compare current measurements against a registered enrolment
// by Hamming distance. No cryptographic key is derived from the physical
// measurement in this phase; that is deferred to W5b after real bit-error
// distributions have been collected from production hosts.
//
// Threat model addressed by W5a:
//   - VM cloned to a different physical host: core frequency ratios shift,
//     Hamming distance exceeds threshold, server emits HARDWARE_TAMPER.
//   - Disk imaged and booted on different silicon: same outcome.
//   - Move to another cloud region / live-migration across hypervisors: same.
//
// Threat model explicitly NOT addressed by W5a:
//   - Rootkit that runs on the same physical host (same core set, similar
//     scheduling). The physical signature is largely preserved; detection
//     depends on the kernel sentinel and MSTC layers, not on PAL.
//   - Adversary that fully controls the scheduler and can replay arbitrary
//     frequency patterns. Mitigated in W5b by key derivation from PUF bits.
package puf

import "time"

// LoopKind identifies the micro-benchmark kernel used for a measurement.
// Different kernels expose different CPU substructures (integer ALU,
// data cache, branch predictor) and therefore contribute independent
// entropy to the composite fingerprint.
type LoopKind uint8

const (
	LoopIntMix    LoopKind = iota // ALU-heavy integer mixing (xorshift + multiply)
	LoopMemStride                 // dependent pointer chase across an L1-sized buffer
	LoopBranch                    // data-dependent branches that stress the predictor
	LoopFloatMul                  // dependent fp64 multiply-add chain (W5b: silicon FPU signature)
	LoopHashRound                 // SipHash-style mix (W5b: shifters + rotators)
)

// String returns a short stable identifier for diagnostics and JSON encoding.
func (lk LoopKind) String() string {
	switch lk {
	case LoopIntMix:
		return "int"
	case LoopMemStride:
		return "mem"
	case LoopBranch:
		return "br"
	case LoopFloatMul:
		return "fp"
	case LoopHashRound:
		return "hash"
	}
	return "?"
}

// AllLoops enumerates the kernels used by the default fingerprint cycle.
// Callers should iterate over this slice rather than hard-coding indexes so
// that future kernels can be added without breaking callers.
//
// The order is fixed by enrolment-time bit positions in QuantizeV2 / V3 / V4
// — appending new loop kinds at the END preserves bit indices for hosts
// that enrolled under earlier loop sets.
var AllLoops = [...]LoopKind{LoopIntMix, LoopMemStride, LoopBranch, LoopFloatMul, LoopHashRound}

// Sample is one (core, loop, trial) measurement. It records the work done
// (Iterations) and the wall-clock time it took (ElapsedNs). Work rate is
// derived lazily so raw values remain available for diagnostic dumps.
type Sample struct {
	Core       int
	Loop       LoopKind
	Trial      int
	Iterations uint64
	ElapsedNs  uint64
}

// ItersPerSec returns the measured work rate in iterations per wall-clock
// second. Zero is returned when ElapsedNs is zero (should not happen outside
// of degenerate runs) so downstream code can filter safely.
func (s Sample) ItersPerSec() float64 {
	if s.ElapsedNs == 0 {
		return 0
	}
	return float64(s.Iterations) * 1e9 / float64(s.ElapsedNs)
}

// Matrix is the raw output of a measurement cycle. Samples are indexed by
// [core][loop][trial]. Sparse entries are not permitted; every cell must
// contain a valid Sample or the matrix is considered invalid.
type Matrix struct {
	NumCores  int
	NumLoops  int
	NumTrials int
	Samples   [][][]Sample
	StartedAt time.Time
	Duration  time.Duration
}

// CoreStats summarises one (core, loop) column of the matrix across trials.
// Median is used instead of mean because even-order statistics are more
// robust to thermal transients and single-trial outliers.
type CoreStats struct {
	Core       int
	Loop       LoopKind
	Median     float64 // iters/sec
	MAD        float64 // median absolute deviation
	CV         float64 // coefficient of variation (StdDev/Mean)
	Min        float64
	Max        float64
	NumSamples int
}

// Fingerprint is the quantized bit vector produced from a Matrix. Length is
// expressed in bits, not bytes; Bits is packed little-endian (bit i of byte
// j represents bit (8*j + i) of the fingerprint). The zero value is not a
// valid fingerprint.
type Fingerprint struct {
	Bits      []byte
	Length    int // number of meaningful bits in Bits
	Cores     int
	Loops     int
	Trials    int
	Digest    string // hex sha3-256 of the packed bits (for quick equality)
	MeasuredAt time.Time
}

// Stats bundles the per-(core,loop) summary statistics that accompany a
// fingerprint. The server stores these alongside the fingerprint to support
// drift triage beyond the raw Hamming distance.
type Stats struct {
	PerCoreLoop []CoreStats
	NumCores    int
	NumLoops    int
	NumTrials   int
	Arch        string
	DurationMs  float64
}

// Baseline captures the enrollment-time behaviour of a host that attestations
// are compared against. It is intentionally thin: storing more than the first
// two moments per cell tempts the server into ML-shaped verdicts that are
// hard to audit. Median and MAD are sufficient for the z-style scoring used
// by CompareToBaseline, and both are small and JSON-friendly.
//
// The ZeroMAD fallback in CompareToBaseline handles the degenerate case
// where a cell's MAD is reported as zero (extremely low measurement noise
// on an idle core); without a floor, any drift becomes an infinite z-score.
type Baseline struct {
	PerCoreLoop []CoreStats // same shape as Stats.PerCoreLoop
	NumCores    int
	NumLoops    int
	NumTrials   int
	Arch        string
	CreatedAt   time.Time
}

// CellDrift describes the deviation of a single (core, loop) cell between
// an attestation and its baseline. Ratio is a relative drift (current/base);
// Z is the MAD-normalised deviation. Both are reported so the control plane
// can triage whether drift is a broad thermal shift (ratios small, Zs large
// if baseline was very tight) or a structural change (ratios large too).
type CellDrift struct {
	Core           int
	Loop           LoopKind
	BaselineMedian float64
	CurrentMedian  float64
	BaselineMAD    float64
	Ratio          float64 // (current - baseline) / baseline
	Z              float64 // (current - baseline) / max(mad, mad_floor)
}

// Report is the result of comparing a Stats against a Baseline. It is the
// canonical payload the server persists for every attestation and the input
// to the verdict thresholds.
type Report struct {
	Cells       []CellDrift
	MaxAbsZ     float64
	MeanAbsZ    float64
	MaxAbsRatio float64
	Verdict     string // "PASS", "DRIFT", "TAMPER"
}
