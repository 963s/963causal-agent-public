// Command 963causal-agent is the runtime integrity sensor.
//
// Lifecycle:
//  1. Load config (/etc/963causal/agent.yaml).
//  2. Load or create durable Ed25519 host key.
//  3. Generate ephemeral X25519 keypair.
//  4. Enroll with the Sentinel control plane (handshake + license check).
//  5. Decrypt probe config in RAM using the derived session key.
//  6. Loop: sample signals, rotate HDR epoch, ship signed frame.
//  7. Heartbeat periodically; if we lose contact past grace_period, wipe
//     the session key and re-enroll.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/963causal/agent/internal/config"
	"github.com/963causal/agent/internal/histogram"
	"github.com/963causal/agent/internal/identity"
	"github.com/963causal/agent/internal/license"
	"github.com/963causal/agent/internal/payload"
	"github.com/963causal/agent/internal/probe"
	"github.com/963causal/agent/internal/puf"
	"github.com/963causal/agent/internal/sculpture"
	"github.com/963causal/agent/internal/sentinel"
	agentpb "github.com/963causal/agent/proto"
)

const AgentVersion = "1.0.0"

func main() {
	cfgPath := flag.String("config", config.DefaultPath, "path to agent.yaml")
	once := flag.Bool("once", false, "ship a single frame and exit (dry-run)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	hk, err := identity.LoadOrCreate(cfg.KeystorePath)
	if err != nil {
		log.Fatalf("keystore: %v", err)
	}

	ctx, cancel := signalContext()
	defer cancel()

	if err := run(ctx, cfg, hk, *once); err != nil {
		log.Fatalf("agent: %v", err)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()
	return ctx, cancel
}

func run(ctx context.Context, cfg *config.Config, hk *identity.HostKey, once bool) error {
	log.Printf("963causal-agent %s starting, control_plane=%s", AgentVersion, cfg.ControlPlaneURL)

	lc := license.NewClient(cfg.ControlPlaneURL, cfg.InsecureSkipTLSVerify)

	ecdh, err := identity.NewECDH()
	if err != nil {
		return fmt.Errorf("ecdh: %w", err)
	}
	defer ecdh.Zero()

	enrollReq := buildEnroll(cfg, hk, ecdh)
	enrollResp, err := lc.Enroll(ctx, enrollReq)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	localCID := identity.CausalIDFromEd25519Pub(hk.EdPublic)
	serverCID := enrollResp.GetCausalId()
	if serverCID != "" && localCID != "" && serverCID != localCID {
		log.Printf("warn: causal_id mismatch local=%s server=%s (using server value)", localCID, serverCID)
	}
	cid := serverCID
	if cid == "" {
		cid = localCID
	}
	log.Printf("enrolled host_id=%s frame_epoch=%ds heartbeat=%ds grace=%ds",
		enrollResp.HostId, enrollResp.FrameEpochSec, enrollResp.HeartbeatIntervalSec, enrollResp.GracePeriodSec)
	if cid != "" {
		log.Printf("causal_id=%s (public integrity portal: https://963causal.com/verify)", cid)
	}

	// ---- Kernel Sentinel: load + replay ----
	// Best effort — if loading fails (missing CAP_BPF, old kernel, no
	// bpffs) the agent keeps running; we simply lose the absence
	// detection capability for this invocation.
	sent, sentinelErr := sentinel.Open(ctx)
	if sentinelErr != nil {
		log.Printf("sentinel: open failed (continuing without): %v", sentinelErr)
	} else {
		defer sent.Close()
		if events, err := sent.DrainAbsences(); err != nil {
			log.Printf("sentinel: drain failed: %v", err)
		} else if len(events) > 0 {
			log.Printf("sentinel: drained %d absence event(s) from previous run", len(events))
			rep := buildAbsenceReport(enrollResp.HostId, events)
			if err := lc.PostAbsenceReport(ctx, enrollResp.AgentToken, rep); err != nil {
				log.Printf("sentinel: report upload failed: %v", err)
			} else {
				log.Printf("sentinel: reported %d absence event(s), batch=%s",
					len(events), rep.ReportBatchId)
			}
		}
		// Always emit a first pulse so the timer has a fresh reference
		// even if we are about to exit (--once mode).
		if err := sent.Pulse(time.Now()); err != nil {
			log.Printf("sentinel: initial pulse failed: %v", err)
		}
	}

	// ---- PUF Attestation Layer (W5a) ----
	// Best effort: if measurement fails the agent continues without PAL.
	// First run enrolls a baseline; subsequent runs attest. Periodic
	// attestation is driven by the main loop below.
	pufSentinel := puf.SentinelPath(cfg.KeystorePath)
	if !puf.Supported() {
		log.Printf("puf: unsupported platform (%s, %d cpus); skipping", os.Getenv("GOOS"), 0)
	} else if enrolled, err := puf.IsEnrolled(pufSentinel); err != nil {
		log.Printf("puf: sentinel stat failed (continuing without): %v", err)
	} else if !enrolled {
		log.Printf("puf: measuring enrollment baseline (one-time)...")
		enrollPB, err := puf.MeasureEnrollment(ctx, enrollResp.HostId, AgentVersion)
		if err != nil {
			log.Printf("puf: enrollment measurement failed: %v", err)
		} else if err := lc.PostPufEnrollment(ctx, enrollResp.AgentToken, enrollPB); err != nil {
			log.Printf("puf: enrollment upload failed: %v", err)
		} else if err := puf.MarkEnrolled(pufSentinel); err != nil {
			log.Printf("puf: mark enrolled failed (will retry next boot): %v", err)
		} else {
			log.Printf("puf: baseline enrolled (%dc × %dl × %dt, %.0fms)",
				enrollPB.NumCores, enrollPB.NumLoops, enrollPB.NumTrials, enrollPB.DurationMs)
		}
	} else {
		log.Printf("puf: already enrolled; first attestation will run on the PUF ticker")
	}

	// ---- PUF Key Derivation (W5b) ----
	// Piggy-backs on the same enrolment gate as W5a: if PAL is not
	// supported or has not been enrolled the W5b enrolment is skipped.
	// The keystore lives next to the host keystore (puf.keystore.json)
	// and carries helper + baseline + derived public key. On a fresh
	// host we run calibration + Enroll; on subsequent boots we just
	// load the state and wait for the proof ticker.
	var pufKey *puf.KeyState
	pufKeyPath := puf.KeyStorePath(cfg.KeystorePath)
	if !puf.KeySupported() {
		log.Printf("puf-key: unsupported platform; skipping W5b")
	} else if state, err := puf.LoadKeyState(pufKeyPath); err != nil {
		log.Printf("puf-key: load state failed (continuing without): %v", err)
	} else if state != nil {
		pufKey = state
		log.Printf("puf-key: loaded existing enrolment (pubkey=%s…, enrolled_at=%s)",
			state.DerivedPubkeyHex()[:16], state.EnrolledAt.Format(time.RFC3339))
	} else {
		log.Printf("puf-key: enrolling fresh (W5b calibration + fuzzy extractor)...")
		newState, keyPB, err := puf.EnrollKey(ctx, enrollResp.HostId, AgentVersion, nil)
		if err != nil {
			log.Printf("puf-key: enrolment failed: %v", err)
		} else if err := lc.PostPufKeyEnrollment(ctx, enrollResp.AgentToken, keyPB); err != nil {
			log.Printf("puf-key: enrolment upload failed (retaining nothing): %v", err)
		} else if err := puf.SaveKeyState(pufKeyPath, newState); err != nil {
			log.Printf("puf-key: save state failed (will re-enrol next boot): %v", err)
		} else {
			pufKey = newState
			log.Printf("puf-key: enrolled (pubkey=%s…, %d reliable bits, BER≤%.2f%%)",
				newState.DerivedPubkeyHex()[:16], newState.ReliablePool, newState.MaxBER*100)
		}
	}

	// Derive session key from ECDH + HKDF, decrypt probe config in RAM.
	shared, err := ecdh.SharedSecret(enrollResp.ServerX25519Pub)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}
	defer payload.Zero(shared)

	sessionKey, err := payload.DeriveSessionKey(shared, enrollResp.HostId, cfg.LicenseKey)
	if err != nil {
		return fmt.Errorf("session key: %w", err)
	}
	defer payload.Zero(sessionKey)

	plain, err := payload.Decrypt(sessionKey, enrollResp.PayloadNonce, enrollResp.EncryptedPayload)
	if err != nil {
		return fmt.Errorf("decrypt probe config: %w", err)
	}
	probeCfg := &agentpb.ProbeConfig{}
	if err := proto.Unmarshal(plain, probeCfg); err != nil {
		return fmt.Errorf("parse probe config: %w", err)
	}
	log.Printf("probe config decrypted: epoch=%ds syscalls=%v version=%d",
		probeCfg.EpochSec, probeCfg.SyscallProbes, probeCfg.Version)

	epoch := time.Duration(probeCfg.EpochSec) * time.Second
	if epoch <= 0 {
		epoch = 10 * time.Second
	}
	heartbeat := time.Duration(enrollResp.HeartbeatIntervalSec) * time.Second
	if heartbeat <= 0 {
		heartbeat = 60 * time.Second
	}

	var sequence uint64
	frameTick := time.NewTicker(epoch)
	defer frameTick.Stop()
	hbTick := time.NewTicker(heartbeat)
	defer hbTick.Stop()
	pulseTick := time.NewTicker(sentinel.PulseInterval)
	defer pulseTick.Stop()
	pufTick := time.NewTicker(puf.AttestInterval)
	defer pufTick.Stop()
	pufKeyTick := time.NewTicker(puf.ProofInterval)
	defer pufKeyTick.Stop()

	ship := func() error {
		sequence++
		frame := buildFrame(ctx, enrollResp.HostId, sequence, probeCfg)
		signed, err := license.SignFrame(hk.EdPrivate, frame)
		if err != nil {
			return err
		}
		return lc.PostFrame(ctx, enrollResp.AgentToken, signed)
	}

	// First frame immediately so the dashboard lights up quickly.
	if err := ship(); err != nil {
		log.Printf("first frame failed: %v", err)
	} else {
		log.Printf("frame #%d shipped", sequence)
	}

	// First PUF-key proof immediately if enrolled, so the dashboard
	// shows a "last proof" timestamp from the outset rather than
	// waiting a full ProofInterval.
	if pufKey != nil {
		if proofPB, err := puf.ProveKey(ctx, enrollResp.HostId, AgentVersion, pufKey); err != nil {
			log.Printf("puf-key: first proof failed: %v", err)
		} else if err := lc.PostPufKeyProof(ctx, enrollResp.AgentToken, proofPB); err != nil {
			log.Printf("puf-key: first proof upload failed: %v", err)
		} else {
			log.Printf("puf-key: first proof shipped (pubkey=%s…)",
				pufKey.DerivedPubkeyHex()[:16])
		}
	}

	if once {
		return nil
	}

	lastContact := time.Now()
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown")
			return nil
		case <-frameTick.C:
			if err := ship(); err != nil {
				log.Printf("frame error: %v", err)
			} else {
				log.Printf("frame #%d shipped", sequence)
				lastContact = time.Now()
			}
		case t := <-pulseTick.C:
			if sent != nil {
				if err := sent.Pulse(t); err != nil {
					log.Printf("sentinel: pulse error: %v", err)
				}
			}
		case <-pufTick.C:
			if !puf.Supported() {
				continue
			}
			enrolled, err := puf.IsEnrolled(pufSentinel)
			if err != nil || !enrolled {
				continue
			}
			attestPB, err := puf.MeasureAttestation(ctx, enrollResp.HostId, AgentVersion)
			if err != nil {
				log.Printf("puf: attestation measurement failed: %v", err)
				continue
			}
			if err := lc.PostPufAttestation(ctx, enrollResp.AgentToken, attestPB); err != nil {
				log.Printf("puf: attestation upload failed: %v", err)
				continue
			}
			log.Printf("puf: attestation shipped (%dc × %dl × %dt, %.0fms)",
				attestPB.NumCores, attestPB.NumLoops, attestPB.NumTrials, attestPB.DurationMs)
		case <-pufKeyTick.C:
			if pufKey == nil {
				continue
			}
			proofPB, err := puf.ProveKey(ctx, enrollResp.HostId, AgentVersion, pufKey)
			if err != nil {
				log.Printf("puf-key: proof measurement failed: %v", err)
				continue
			}
			if err := lc.PostPufKeyProof(ctx, enrollResp.AgentToken, proofPB); err != nil {
				log.Printf("puf-key: proof upload failed: %v", err)
				continue
			}
			log.Printf("puf-key: proof shipped (pubkey=%s…)",
				pufKey.DerivedPubkeyHex()[:16])
		case <-hbTick.C:
			hb := &agentpb.HeartbeatRequest{
				HostId:        enrollResp.HostId,
				Sequence:      sequence,
				TimestampUnix: time.Now().Unix(),
			}
			hb.Signature = license.SignHeartbeat(hk.EdPrivate, hb.HostId, hb.Sequence, hb.TimestampUnix)
			resp, err := lc.Heartbeat(ctx, enrollResp.AgentToken, hb)
			if err != nil {
				log.Printf("heartbeat error: %v", err)
				if time.Since(lastContact) > time.Duration(enrollResp.GracePeriodSec)*time.Second {
					log.Printf("grace period expired; zeroing session key and halting")
					payload.Zero(sessionKey)
					return fmt.Errorf("grace expired")
				}
				continue
			}
			lastContact = time.Now()
			if !resp.LicenseValid {
				log.Printf("license invalid; halting")
				return fmt.Errorf("license revoked")
			}
		}
	}
}

// buildAbsenceReport converts sentinel.AbsenceEvent values into a
// protobuf AbsenceReport ready to ship to the control plane.
func buildAbsenceReport(hostID string, events []sentinel.AbsenceEvent) *agentpb.AbsenceReport {
	out := &agentpb.AbsenceReport{
		HostId:        hostID,
		ReportBatchId: randomBatchID(),
		DrainedAtMs:   time.Now().UnixMilli(),
		Events:        make([]*agentpb.AbsenceEvent, 0, len(events)),
	}
	for _, e := range events {
		var lastSeenMs int64
		if !e.NeverSawPulse {
			lastSeenMs = e.AgentLastSeen.UnixMilli()
		}
		out.Events = append(out.Events, &agentpb.AbsenceEvent{
			DetectedAtMs:    e.DetectedAt.UnixMilli(),
			AgentLastSeenMs: lastSeenMs,
			GapSeconds:      e.GapSeconds,
			Cpu:             e.Cpu,
			Flags:           e.Flags,
			Comm:            e.Comm,
			LastSeq:         e.LastSeq,
		})
	}
	return out
}

func randomBatchID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("abs_%x", b[:])
}

func buildEnroll(cfg *config.Config, hk *identity.HostKey, ecdh *identity.ECDHKey) *agentpb.EnrollRequest {
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := int64(binary.BigEndian.Uint64(nonceBytes) & 0x7fffffffffffffff)

	hostname, _ := os.Hostname()
	return &agentpb.EnrollRequest{
		LicenseKey:     cfg.LicenseKey,
		PublicKey:      hk.EdPublic,
		X25519Public:   ecdh.Public[:],
		HwFingerprint:  identity.HardwareFingerprint(),
		AgentVersion:   AgentVersion,
		Hostname:       hostname,
		OsRelease:      osRelease(),
		Kernel:         kernelRelease(),
		CpuModel:       cpuModel(),
		TotalMemoryKb:  memTotalKb(),
		Nonce:          nonce,
		TimestampUnix:  time.Now().Unix(),
	}
}

func buildFrame(ctx context.Context, hostID string, sequence uint64, pc *agentpb.ProbeConfig) *agentpb.Frame {
	const samplesPer = 256
	start := time.Now()

	var hists []*agentpb.HdrHistogram
	for _, sc := range pc.SyscallProbes {
		ep := histogram.NewEpoch(sc)
		ep.AddAll(probe.SyscallLatency(sc, samplesPer))
		hists = append(hists, ep.Digest())
	}

	sched := probe.ReadSchedStat()
	faults := probe.ReadPageFaults()

	vertices := sculpture.BuildVertices(hists)
	genotype := sculpture.Genotype(vertices)

	// W3 Physics Layer probes.
	// MSTC runs in-process; the whole loop costs < 5 ms on 2 vCPU.
	mstc := probe.SampleMSTC()
	// External Witness fetches a drand round over HTTPS. Bounded to a
	// short timeout so a flapping network cannot delay frame shipping.
	witnessCtx, witnessCancel := context.WithTimeout(ctx, 2*time.Second)
	witness := probe.SampleExternalWitness(witnessCtx)
	witnessCancel()

	return &agentpb.Frame{
		HostId:     hostID,
		Sequence:   sequence,
		EpochStart: start.UnixMilli(),
		EpochEnd:   time.Now().UnixMilli(),
		SyscallHist: hists,
		Sched: &agentpb.SchedulerDigest{
			ContextSwitches: sched.ContextSwitches,
			Load_1M:         sched.Load1m,
		},
		Faults: &agentpb.FaultDigest{
			MinorFaults: faults.Minor,
			MajorFaults: faults.Major,
		},
		Vertices:       vertices,
		Genotype:       genotype,
		HwFingerprint:  identity.HardwareFingerprint(),
		TimeConsensus:  mstc,
		Witness:        witness,
	}
}
