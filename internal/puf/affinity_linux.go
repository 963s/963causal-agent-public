//go:build linux

package puf

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// pinToCore locks the calling goroutine to the given logical CPU. The caller
// is responsible for runtime.LockOSThread() and the matching Unlock call; we
// cannot do it here because the affinity set survives only for the lifetime
// of the OS thread, and we need the caller to control when that thread is
// released.
//
// The call returns an error when coreID is out of range or when the kernel
// refuses the affinity change (EPERM inside some container runtimes, for
// example). Callers should treat an error as "skip this core" rather than
// abort the whole measurement cycle, because PAL gracefully degrades with
// fewer cores.
func pinToCore(coreID int) error {
	if coreID < 0 {
		return fmt.Errorf("puf: negative core id %d", coreID)
	}
	var set unix.CPUSet
	set.Zero()
	set.Set(coreID)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return fmt.Errorf("puf: sched_setaffinity(cpu=%d): %w", coreID, err)
	}
	return nil
}

// numLogicalCores returns the number of logical CPUs reported to Go. On
// Linux this reflects the current cgroup / cpuset restriction, which is
// exactly what we want: the PUF signature is derived from the cores the
// agent is actually allowed to use.
func numLogicalCores() int {
	return runtime.NumCPU()
}
