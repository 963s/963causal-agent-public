//go:build arm64

package probe

import "os"

// Symbols defined in timer_arm64.s
func readCNTVCT() uint64
func readCNTPCT() uint64
func readCNTFRQ() uint64

// ArchName identifies the target CPU family for TimeConsensus.
const ArchName = "arm64"

// hwCounter returns the primary hardware counter (virtual count).
// CNTVCT_EL0 is architecturally guaranteed to be readable from EL0
// (ARM BSA / ARMv8-A), so this always succeeds.
func hwCounter() uint64 { return readCNTVCT() }

// cntpctEnabled is true only when the host allows EL0 reads of the
// physical counter. Most virtualised ARM64 guests trap CNTPCT_EL0 to
// EL2 (EL0PCTEN = 0) and the hypervisor then delivers SIGILL, which
// would terminate the agent. We therefore default to off and require
// an explicit opt-in on bare-metal hosts via CAUSAL_963_ENABLE_CNTPCT=1.
var cntpctEnabled = os.Getenv("CAUSAL_963_ENABLE_CNTPCT") == "1"

// hwCounterAlt returns an alternate hardware-counter read path.
//
//   * On bare metal (or hypervisors with EL0PCTEN=1), and when
//     CAUSAL_963_ENABLE_CNTPCT=1 is set, this reads CNTPCT_EL0. The
//     ratio Δ(VCT)/Δ(PCT) is exactly 1.0 and only diverges under
//     dynamic hypervisor time manipulation (migration / pause-resume).
//   * Otherwise we read CNTVCT_EL0 again. The ratio is a trivial 1.0
//     but the per-sample latency distribution of this path is still
//     a useful second sample of CNTVCT access latency.
//
// The fact that we had to disable the alternate path IS the signal on
// this class of host: it tells us we are inside a virtualised guest
// where CNTPCT_EL0 is trapped. That fact is recorded by the server.
func hwCounterAlt() uint64 {
	if cntpctEnabled {
		return readCNTPCT()
	}
	return readCNTVCT()
}

// hwFrequency returns the counter frequency in Hz.
func hwFrequency() uint64 { return readCNTFRQ() }
