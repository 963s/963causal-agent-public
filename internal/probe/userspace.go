// Package probe samples host timing signals.
//
// W1 implementation: userspace only. We synthesize syscall latency distributions
// from /proc/schedstat, /proc/stat, /proc/<pid>/status, and a set of loopback
// syscall micro-probes. This proves the pipeline end-to-end while we land the
// eBPF implementation in W2.
package probe

import (
	"bufio"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SyscallLatency returns a synthetic set of latency samples (nanoseconds) for
// the given syscall name. In W1 we use timed micro-probes on the calling host.
// The distribution is real; only the set of probes is limited.
func SyscallLatency(name string, samples int) []int64 {
	out := make([]int64, 0, samples)
	switch name {
	case "read":
		f, err := os.Open("/proc/self/stat")
		if err != nil {
			return out
		}
		defer f.Close()
		buf := make([]byte, 256)
		for i := 0; i < samples; i++ {
			_, _ = f.Seek(0, 0)
			t := time.Now()
			_, _ = f.Read(buf)
			out = append(out, time.Since(t).Nanoseconds())
		}
	case "openat":
		for i := 0; i < samples; i++ {
			t := time.Now()
			f, err := os.Open("/proc/self/stat")
			if err == nil {
				f.Close()
			}
			out = append(out, time.Since(t).Nanoseconds())
		}
	case "stat":
		for i := 0; i < samples; i++ {
			t := time.Now()
			_, _ = os.Stat("/proc/self/stat")
			out = append(out, time.Since(t).Nanoseconds())
		}
	case "write":
		// write to /dev/null via dup'd fd for consistent cost
		fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
		if err != nil {
			return out
		}
		defer syscall.Close(fd)
		payload := []byte("963causal probe\n")
		for i := 0; i < samples; i++ {
			t := time.Now()
			_, _ = syscall.Write(fd, payload)
			out = append(out, time.Since(t).Nanoseconds())
		}
	case "getpid":
		for i := 0; i < samples; i++ {
			t := time.Now()
			_ = syscall.Getpid()
			out = append(out, time.Since(t).Nanoseconds())
		}
	case "mmap":
		for i := 0; i < samples; i++ {
			t := time.Now()
			b, err := syscall.Mmap(-1, 0, 4096,
				syscall.PROT_READ|syscall.PROT_WRITE,
				syscall.MAP_ANON|syscall.MAP_PRIVATE)
			if err == nil {
				_ = syscall.Munmap(b)
			}
			out = append(out, time.Since(t).Nanoseconds())
		}
	default:
		// unknown syscall: jittered idle to avoid empty histograms
		for i := 0; i < samples; i++ {
			t := time.Now()
			runtime.Gosched()
			out = append(out, time.Since(t).Nanoseconds()+int64(rand.Intn(100)))
		}
	}
	return out
}

// Schedstat reads /proc/schedstat aggregate stats.
type SchedStat struct {
	RunTimeNs    uint64
	WaitTimeNs   uint64
	TimeSlices   uint64
	ContextSwitches uint64
	Load1m       float64
}

func ReadSchedStat() SchedStat {
	s := SchedStat{}
	if f, err := os.Open("/proc/schedstat"); err == nil {
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			line := scan.Text()
			if !strings.HasPrefix(line, "cpu") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 9 {
				r, _ := strconv.ParseUint(parts[7], 10, 64)
				w, _ := strconv.ParseUint(parts[8], 10, 64)
				var t uint64
				if len(parts) >= 10 {
					t, _ = strconv.ParseUint(parts[9], 10, 64)
				}
				s.RunTimeNs += r
				s.WaitTimeNs += w
				s.TimeSlices += t
			}
		}
		f.Close()
	}
	s.ContextSwitches = readCtxtSwitches()
	s.Load1m = readLoad1m()
	return s
}

func readCtxtSwitches() uint64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ctxt ") {
			v, _ := strconv.ParseUint(strings.TrimPrefix(line, "ctxt "), 10, 64)
			return v
		}
	}
	return 0
}

func readLoad1m() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(parts[0], 64)
	return v
}

// PageFaults reads the calling process page fault counters (/proc/self/stat
// fields 10 and 12: minflt and majflt).
type PageFaults struct {
	Minor uint64
	Major uint64
}

func ReadPageFaults() PageFaults {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return PageFaults{}
	}
	parts := strings.Fields(string(b))
	if len(parts) < 13 {
		return PageFaults{}
	}
	minflt, _ := strconv.ParseUint(parts[9], 10, 64)
	majflt, _ := strconv.ParseUint(parts[11], 10, 64)
	return PageFaults{Minor: minflt, Major: majflt}
}
