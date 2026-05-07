//go:build !linux

package puf

import (
	"fmt"
	"runtime"
)

// pinToCore is a no-op on non-Linux platforms. We still expose the function
// so the rest of the package compiles cleanly elsewhere, but measurements
// taken without CPU pinning cannot be trusted as PUF input; the agent's
// main loop must gate PAL enablement on runtime.GOOS == "linux".
func pinToCore(coreID int) error {
	return fmt.Errorf("puf: pinning unsupported on %s", runtime.GOOS)
}

func numLogicalCores() int {
	return runtime.NumCPU()
}
