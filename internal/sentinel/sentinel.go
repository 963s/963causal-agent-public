// Package sentinel owns the Kernel Sentinel: a pinned eBPF program
// that continues running inside the kernel when the userspace agent is
// killed. The agent heartbeats into `pulse_map`; a kernel BPF_TIMER
// detects silence and records `absence_event`s on a ringbuf. On the
// next agent start, we drain the ringbuf and ship findings to the
// server.
//
// Pinning layout (bpffs):
//   /sys/fs/bpf/963causal/pulse_map
//   /sys/fs/bpf/963causal/timer_map
//   /sys/fs/bpf/963causal/absence_ringbuf
//   /sys/fs/bpf/963causal/start_timer   (the BPF program itself)

package sentinel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// PinRoot is the bpffs directory where all sentinel objects live.
	PinRoot = "/sys/fs/bpf/963causal"

	// PulseInterval must be less than PULSE_TIMEOUT_NS in sentinel.c
	// (120s) so the kernel has margin before declaring us absent.
	PulseInterval = 30 * time.Second
)

// Sentinel wraps the loaded eBPF collection. Exactly one instance
// should exist per agent process.
type Sentinel struct {
	coll *ebpf.Collection

	pulseMap       *ebpf.Map
	timerMap       *ebpf.Map
	absenceRingbuf *ebpf.Map
	startProg      *ebpf.Program

	seq uint64
}

// AbsenceEvent is the userspace view of what the kernel timer wrote.
type AbsenceEvent struct {
	DetectedAt     time.Time
	AgentLastSeen  time.Time // reconstructed from LastWallclockNs; zero if never
	GapSeconds     float64
	Cpu            uint32
	Flags          uint32
	Comm           string
	NeverSawPulse  bool
	LastSeq        uint64
}

// Open loads the embedded Sentinel collection, attempting to attach to
// already-pinned maps/programs where possible. On success the timer is
// running and the agent can pulse via Pulse().
func Open(ctx context.Context) (*Sentinel, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	if err := os.MkdirAll(PinRoot, 0o700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("mkdir %s: %w", PinRoot, err)
	}

	spec, err := LoadSentinel()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: PinRoot},
	})
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	s := &Sentinel{
		coll:           coll,
		pulseMap:       coll.Maps["pulse_map"],
		timerMap:       coll.Maps["timer_map"],
		absenceRingbuf: coll.Maps["absence_ringbuf"],
		startProg:      coll.Programs["start_timer"],
	}
	if s.pulseMap == nil || s.timerMap == nil || s.absenceRingbuf == nil || s.startProg == nil {
		s.Close()
		return nil, errors.New("sentinel collection missing required objects")
	}

	// Pin the program so it survives our death. Maps are already
	// pinned via LIBBPF_PIN_BY_NAME above.
	progPin := filepath.Join(PinRoot, "start_timer")
	if _, err := os.Stat(progPin); err == nil {
		// stale pin — remove and repin, so a rebuild doesn't break
		// on an old bytecode signature.
		_ = os.Remove(progPin)
	}
	if err := s.startProg.Pin(progPin); err != nil {
		s.Close()
		return nil, fmt.Errorf("pin start_timer: %w", err)
	}

	// Kick the timer exactly once. The callback re-arms itself.
	if _, _, err := runProg(ctx, s.startProg); err != nil {
		s.Close()
		return nil, fmt.Errorf("start timer: %w", err)
	}

	return s, nil
}

// Pulse writes a fresh heartbeat into pulse_map. Safe to call from any
// goroutine; the BPF hash map supports atomic updates.
func (s *Sentinel) Pulse(now time.Time) error {
	s.seq++
	nanos := uint64(now.UnixNano())
	// ktime_get_ns — used by the kernel timer — is CLOCK_MONOTONIC
	// since boot. Userspace doesn't have a portable way to sample
	// that from Go, so we stash wall-clock + seq and let the kernel
	// compare against its own ktime via the ringbuf gap.
	//
	// For the pulse freshness check the kernel uses its own ktime
	// snapshot when we set the value, so we store that below.
	val := SentinelPulseValue{
		TimestampNs: kernelMonotonicNs(), // see helper below
		WallclockNs: nanos,
		Seq:         s.seq,
	}
	key := SentinelPulseKey{HostId: 0}
	return s.pulseMap.Update(&key, &val, ebpf.UpdateAny)
}

// DrainAbsences reads any absence events left in the ringbuf by a
// previous run of the sentinel, returning them as Go values. The
// function is non-blocking: it stops once the ringbuf is empty.
func (s *Sentinel) DrainAbsences() ([]AbsenceEvent, error) {
	reader, err := ringbuf.NewReader(s.absenceRingbuf)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer reader.Close()

	// Non-blocking drain: a zero deadline returns `os.ErrDeadlineExceeded`
	// when the buffer is empty.
	reader.SetDeadline(time.Now())

	var out []AbsenceEvent
	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrClosed) {
				return out, nil
			}
			return out, fmt.Errorf("ringbuf read: %w", err)
		}
		evt, perr := parseAbsence(rec.RawSample)
		if perr != nil {
			// Skip malformed records rather than abort the drain; they
			// are almost certainly a version mismatch across a rebuild.
			continue
		}
		out = append(out, evt)
	}
}

// Close tears down the in-process collection but leaves the pinned
// objects in /sys/fs/bpf intact. That is by design: the whole point of
// the sentinel is for the pinned timer to outlive the agent.
func (s *Sentinel) Close() error {
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

// Unpin removes all pinned sentinel objects from bpffs. Only call this
// when intentionally shutting the sentinel down for good.
func Unpin() error {
	for _, name := range []string{"start_timer", "timer_map", "pulse_map", "absence_ringbuf"} {
		p := filepath.Join(PinRoot, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// --- internals ---

func parseAbsence(raw []byte) (AbsenceEvent, error) {
	var e AbsenceEvent
	if len(raw) < 48 {
		return e, fmt.Errorf("short absence event: %d bytes", len(raw))
	}
	var se SentinelAbsenceEvent
	// The struct is C-packed but bpf2go added alignment; size should
	// match exactly. Bail if anything is off so we surface ABI skew.
	expected := binary.Size(&se)
	if expected < 0 || len(raw) < expected {
		return e, fmt.Errorf("absence event size mismatch: got %d need %d", len(raw), expected)
	}
	// Little-endian — all Linux-supported BPF archs are LE.
	se.NowNs = binary.LittleEndian.Uint64(raw[0:8])
	se.LastPulseNs = binary.LittleEndian.Uint64(raw[8:16])
	se.LastWallclockNs = binary.LittleEndian.Uint64(raw[16:24])
	se.LastSeq = binary.LittleEndian.Uint64(raw[24:32])
	se.Cpu = binary.LittleEndian.Uint32(raw[32:36])
	se.Flags = binary.LittleEndian.Uint32(raw[36:40])
	copy(se.Comm[:], raw[40:56])

	now := time.Now()
	bootAnchor := now.Add(-time.Duration(kernelMonotonicNs()) * time.Nanosecond)
	e.DetectedAt = bootAnchor.Add(time.Duration(se.NowNs) * time.Nanosecond)
	if se.Flags&0x01 == 0 && se.LastWallclockNs > 0 {
		e.AgentLastSeen = time.Unix(0, int64(se.LastWallclockNs))
		e.GapSeconds = float64(se.NowNs-se.LastPulseNs) / 1e9
	} else {
		e.NeverSawPulse = true
	}
	e.Cpu = se.Cpu
	e.Flags = se.Flags
	e.Comm = trimCString(se.Comm[:])
	e.LastSeq = se.LastSeq
	return e, nil
}

func trimCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
