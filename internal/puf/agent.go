package puf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	agentpb "github.com/963causal/agent/proto"
)

// AttestInterval is how often the agent takes a fresh PUF measurement and
// ships it to the server for comparison. Six hours is the default: it is
// short enough to catch a live VM migration within a working day, long
// enough to amortise the ~1-second measurement cost across a day.
const AttestInterval = 6 * time.Hour

// enrolledSentinelName is the marker file the agent drops once the server
// has accepted a PufEnrollment. The file's presence means "do not re-enroll,
// just attest"; its absence means "enroll first". It lives next to the
// keystore so it rotates together with the host's Ed25519 key.
const enrolledSentinelName = "puf.enrolled"

// Supported returns true when the running platform can produce a valid
// PUF measurement. Currently this means Linux with at least 2 logical
// cores; on other platforms we degrade silently rather than failing the
// agent boot.
func Supported() bool {
	return runtime.GOOS == "linux" && runtime.NumCPU() >= 2
}

// SentinelPath returns the full path to the per-host "puf enrolled" marker
// file derived from the keystore path. The caller is responsible for
// ensuring the directory exists; LoadOrCreate on identity does that
// transitively through NewHostKey, so by the time we reach PUF bootstrap
// the directory is already present.
func SentinelPath(keystorePath string) string {
	dir := filepath.Dir(keystorePath)
	return filepath.Join(dir, enrolledSentinelName)
}

// IsEnrolled reports whether the PUF enrollment marker file exists.
// Missing file means "not enrolled"; any stat error other than NotExist
// is surfaced so operators can notice permission issues.
func IsEnrolled(sentinelPath string) (bool, error) {
	_, err := os.Stat(sentinelPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("puf: stat sentinel %q: %w", sentinelPath, err)
}

// MarkEnrolled creates the marker file atomically via O_EXCL|O_CREATE.
// Calling it twice is not an error; we just touch the file and move on.
func MarkEnrolled(sentinelPath string) error {
	// Open with O_CREATE rather than O_EXCL so idempotent callers don't
	// have to check IsEnrolled first. We also truncate to zero bytes so
	// the file stays recognisable as a pure sentinel.
	f, err := os.OpenFile(sentinelPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("puf: mark enrolled %q: %w", sentinelPath, err)
	}
	return f.Close()
}

// MeasureEnrollment runs a full measurement cycle tuned for an enrolment
// payload — more trials than a routine attestation to reduce baseline
// noise at one-time cost. The returned proto message is ready to ship to
// the control plane.
func MeasureEnrollment(ctx context.Context, hostID, agentVersion string) (*agentpb.PufEnrollment, error) {
	_ = ctx // measurement is synchronous and short; ctx is accepted for future cancellation
	cfg := Config{
		Trials:       64,
		WarmupTrials: DefaultWarmupTrials,
		TargetLoopMs: DefaultTargetLoopMs,
	}
	m, err := Measure(cfg)
	if err != nil {
		return nil, fmt.Errorf("measure enrollment: %w", err)
	}
	stats := Summarise(m)
	return toEnrollmentPB(hostID, agentVersion, stats), nil
}

// MeasureAttestation runs a routine measurement cycle suitable for
// periodic attestation. Trials are reduced relative to enrollment to keep
// per-attestation CPU cost low (~1 second on 4 cores).
func MeasureAttestation(ctx context.Context, hostID, agentVersion string) (*agentpb.PufAttestation, error) {
	_ = ctx
	cfg := Config{
		Trials:       DefaultTrials,
		WarmupTrials: DefaultWarmupTrials,
		TargetLoopMs: DefaultTargetLoopMs,
	}
	m, err := Measure(cfg)
	if err != nil {
		return nil, fmt.Errorf("measure attestation: %w", err)
	}
	stats := Summarise(m)
	return toAttestationPB(hostID, agentVersion, stats), nil
}

func toEnrollmentPB(hostID, agentVersion string, s Stats) *agentpb.PufEnrollment {
	return &agentpb.PufEnrollment{
		HostId:        hostID,
		Cells:         cellsToPB(s.PerCoreLoop),
		NumCores:      uint32(s.NumCores),
		NumLoops:      uint32(s.NumLoops),
		NumTrials:     uint32(s.NumTrials),
		Arch:          s.Arch,
		DurationMs:    s.DurationMs,
		MeasuredAtMs:  time.Now().UnixMilli(),
		AgentVersion:  agentVersion,
	}
}

func toAttestationPB(hostID, agentVersion string, s Stats) *agentpb.PufAttestation {
	return &agentpb.PufAttestation{
		HostId:        hostID,
		Cells:         cellsToPB(s.PerCoreLoop),
		NumCores:      uint32(s.NumCores),
		NumLoops:      uint32(s.NumLoops),
		NumTrials:     uint32(s.NumTrials),
		Arch:          s.Arch,
		DurationMs:    s.DurationMs,
		MeasuredAtMs:  time.Now().UnixMilli(),
		AgentVersion:  agentVersion,
	}
}

func cellsToPB(cs []CoreStats) []*agentpb.PufCellStats {
	out := make([]*agentpb.PufCellStats, 0, len(cs))
	for _, c := range cs {
		out = append(out, &agentpb.PufCellStats{
			Core:       uint32(c.Core),
			Loop:       c.Loop.String(),
			MedianIps:  c.Median,
			MadIps:     c.MAD,
			Cv:         c.CV,
			MinIps:     c.Min,
			MaxIps:     c.Max,
			NumSamples: uint32(c.NumSamples),
		})
	}
	return out
}
