//go:build linux

package identity

import "golang.org/x/sys/unix"

// sysconfMemory returns (pages, pageSize) using the sysinfo(2) syscall.
// sysinfo reads from the kernel's own memory accounting structures and
// is NOT affected by /proc-layer rootkits — a FUSE overlay on /proc or
// an intercepted sys_read cannot change what sysinfo(2) returns.
func sysconfMemory() (pages, pageSize int64) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, 0
	}
	// Totalram is in units of info.Unit bytes (always 1 on Linux x86/arm64).
	totalBytes := int64(info.Totalram) * int64(info.Unit)
	const linuxPageSize = 4096
	return totalBytes / linuxPageSize, linuxPageSize
}
