//go:build !linux

package identity

// sysconfMemory is a no-op stub on non-Linux platforms; the caller falls
// back to /proc/meminfo (or returns empty string on non-Linux).
func sysconfMemory() (pages, pageSize int64) { return 0, 0 }
