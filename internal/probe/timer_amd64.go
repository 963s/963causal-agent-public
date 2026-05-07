//go:build amd64

package probe

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Symbols defined in timer_amd64.s
func readTSC() uint64
func readTSCP() uint64

const ArchName = "amd64"

// hwCounter returns the Time Stamp Counter (rdtsc).
func hwCounter() uint64 { return readTSC() }

// hwCounterAlt returns the serialized TSC (rdtscp). Some hypervisors trap
// RDTSCP but not RDTSC; the ratio Δ(TSC)/Δ(TSCP) stays at 1.0 on bare metal
// and diverges slightly (or latency inflates) when RDTSCP is trapped.
func hwCounterAlt() uint64 { return readTSCP() }

// hwFrequency estimates TSC Hz. The architectural CPUID leaf 0x15 gives
// it exactly on modern parts, but many Linux hosts expose it via
// /proc/cpuinfo "tsc" flag + the cpu MHz value. We fall back to a
// calibrated 50 ms measurement against CLOCK_MONOTONIC_RAW.
func hwFrequency() uint64 {
	if hz := parseTscHzFromSys(); hz != 0 {
		return hz
	}
	// Calibration fallback: count TSC ticks over a short wall interval.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const window = 50 * time.Millisecond
	start := readTSC()
	wallStart := time.Now()
	for time.Since(wallStart) < window {
	}
	elapsed := time.Since(wallStart)
	ticks := readTSC() - start
	if elapsed == 0 {
		return 0
	}
	return uint64(float64(ticks) * float64(time.Second) / float64(elapsed))
}

func parseTscHzFromSys() uint64 {
	// The kernel records the nominal TSC frequency in /sys on TSC-stable
	// hosts (only available on some distributions + CPUs).
	paths := []string{
		"/sys/devices/system/cpu/cpu0/tsc_freq_khz",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			if err == nil && v > 0 {
				return v * 1000
			}
		}
	}
	return 0
}
