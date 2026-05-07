//go:build linux

package sentinel

import (
	"context"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// kernelMonotonicNs returns the kernel's CLOCK_MONOTONIC reading in
// nanoseconds. This matches bpf_ktime_get_ns() semantics on the same
// host, so timer-side comparisons against pulse_value.timestamp_ns are
// consistent.
func kernelMonotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// runProg invokes a BPF_PROG_TYPE_SYSCALL program once, returning its
// return code. cilium/ebpf v0.21 exposes this via (*Program).Run.
func runProg(ctx context.Context, p *ebpf.Program) (uint32, []byte, error) {
	_ = ctx // reserved for future per-call timeouts
	ret, err := p.Run(&ebpf.RunOptions{})
	return ret, nil, err
}
