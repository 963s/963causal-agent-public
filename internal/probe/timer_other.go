//go:build !arm64 && !amd64

package probe

import "time"

const ArchName = "unknown"

// Fallback: use the monotonic clock as both hardware sources. MSTC ratio
// statistics are still computed but will show zero divergence because
// both paths are identical. The probe is effectively a no-op on unsupported
// architectures until a native counter is added.
func hwCounter() uint64    { return uint64(time.Now().UnixNano()) }
func hwCounterAlt() uint64 { return uint64(time.Now().UnixNano()) }
func hwFrequency() uint64  { return uint64(time.Second) } // 1 ns ticks
