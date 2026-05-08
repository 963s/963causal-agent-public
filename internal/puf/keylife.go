// Package puf — W5b lifecycle helpers.
//
// keylife.go is the agent-side glue between the Measure→Quantise→Enroll
// primitives in the rest of this package and the Sentinel control plane.
// It owns:
//
//   • a small JSON blob on disk (the "key-store file") that captures
//     helper data, the baseline used when the helper was derived, and
//     the derived public key — everything needed to re-run Reproduce on
//     every attestation tick without calling home;
//
//   • a pair of orchestration functions (EnrollKey, ProveKey) that the
//     main loop in cmd/963causal-agent calls at the appropriate moments.
//
// The private key itself is never stored. It is re-derived from K on
// demand and dropped as soon as the proof signature has been produced,
// keeping the window during which a memory dump would leak the key to
// the critical section of a single function call.
package puf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	agentpb "github.com/963causal/agent/proto"
)

// KeyStoreName is the filename (next to the host keystore) that carries
// the W5b helper blob. Its presence means "we have enrolled a PUF-key
// on this host and can reproduce it"; its absence means "run the
// calibration + enrol flow next time the agent boots".
const KeyStoreName = "puf.keystore.json"

// ProofInterval is how often the agent re-proves possession of the
// PUF-derived key. Runs alongside — not inside — the z-score
// attestation tick; a shorter interval than AttestInterval keeps the
// signature fresh on the dashboard without adding meaningful CPU (the
// proof itself is cheap, the measurement it piggy-backs on is not).
const ProofInterval = 6 * time.Hour

// DefaultCalibrationCycles is the number of Measure+QuantizeV3 rounds
// the enrolment flow uses to pick reliable bits. 40 was chosen because
// cmd/puf-ber at 50 cycles finds ~275 stable bits on Ampere Altra and
// the marginal gain past 40 is small while the wall-clock cost grows
// linearly. See BSL §11.3 ADR-002.
const DefaultCalibrationCycles = 40

// DefaultCooldown is the inter-cycle cooldown during calibration. Short
// enough to keep enrolment under ~3 minutes, long enough to let each
// core drop back to the "idle" micro-arch state between measurements so
// the timing distribution stays stationary.
const DefaultCooldown = 250 * time.Millisecond

// DefaultMaxBER is the BER ceiling for reliable-bit selection. 2 % is
// well inside Hamming(7,4)'s 1-bit-per-7 correction capacity after
// accounting for the worst-case run-to-run fluctuation observed during
// W5b characterisation.
const DefaultMaxBER = 0.02

// KeyState is the on-disk representation of a completed enrolment.
// Public and private-key-free by design; K is re-derived on demand.
type KeyState struct {
	Version      uint8      `json:"version"`
	Helper       HelperData `json:"helper"`
	Baseline     Baseline   `json:"baseline"`
	DerivedPub   []byte     `json:"derived_pub"` // 32-byte Ed25519 public half
	EnrolledAt   time.Time  `json:"enrolled_at"`
	AgentVersion string     `json:"agent_version"`

	// Informational, carried forward into each PufKeyEnrollment for
	// server-side dashboards and forensic triage. Not used in the
	// Reproduce path.
	CalibrationCycles int     `json:"calibration_cycles"`
	MaxBER            float64 `json:"max_ber"`
	ReliablePool      int     `json:"reliable_pool"`
}

// KeyStorePath returns the canonical location of the W5b keystore
// derived from the host keystore path. We co-locate them so a single
// operator command (wiping ~/.config/963causal-agent) clears both at
// once.
func KeyStorePath(keystorePath string) string {
	dir := filepath.Dir(keystorePath)
	return filepath.Join(dir, KeyStoreName)
}

// LoadKeyState reads a keystore blob from disk. A missing file is
// returned as (nil, nil); callers use that signal to decide whether an
// enrolment needs to run.
func LoadKeyState(path string) (*KeyState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("puf: read keystore %q: %w", path, err)
	}
	state := &KeyState{}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("puf: parse keystore %q: %w", path, err)
	}
	return state, nil
}

// SaveKeyState writes the keystore atomically (write to tmp + rename).
// Mode 0600 keeps the helper blob readable only by the agent user;
// while the helper is technically public, leaking it to other local
// users buys an attacker nothing of value but adds no cost to guard.
func SaveKeyState(path string, state *KeyState) error {
	buf, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("puf: marshal keystore: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("puf: write keystore tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("puf: rename keystore: %w", err)
	}
	return nil
}

// EnrollKeyOptions lets callers override the calibration parameters.
// Zero values fall back to DefaultCalibrationCycles / DefaultMaxBER /
// DefaultCooldown so normal agent boots don't need to spell them out.
type EnrollKeyOptions struct {
	CalibrationCycles int
	MaxBER            float64
	Cooldown          time.Duration
	Trials            int
}

func (o *EnrollKeyOptions) withDefaults() EnrollKeyOptions {
	out := EnrollKeyOptions{}
	if o != nil {
		out = *o
	}
	if out.CalibrationCycles <= 0 {
		out.CalibrationCycles = DefaultCalibrationCycles
	}
	if out.MaxBER <= 0 {
		out.MaxBER = DefaultMaxBER
	}
	if out.Cooldown <= 0 {
		out.Cooldown = DefaultCooldown
	}
	if out.Trials <= 0 {
		out.Trials = DefaultTrials
	}
	return out
}

// EnrollKey runs the full W5b enrolment flow:
//
//  1. Take M = opts.CalibrationCycles measurements, quantise each with
//     QuantizeV3 against a fresh baseline captured at cycle 0.
//  2. Compute per-bit BER across those fingerprints and pick the
//     positions whose BER ≤ opts.MaxBER.
//  3. Run the fuzzy-extractor Enroll on cycle 0's fingerprint with the
//     reliable indices → random 128-bit K + HelperData.
//  4. Derive the Ed25519 keypair from K and discard K.
//  5. Persist a KeyState (helper + baseline + public key) to disk.
//
// Returns (KeyState, PufKeyEnrollmentProto) so the caller can both
// save locally and ship the public artefacts server-side. Context is
// respected between cycles; an aborted enrolment leaves no disk state.
func EnrollKey(
	ctx context.Context,
	hostID, agentVersion string,
	opts *EnrollKeyOptions,
) (*KeyState, *agentpb.PufKeyEnrollment, error) {
	o := opts.withDefaults()
	if o.CalibrationCycles < 8 {
		return nil, nil, fmt.Errorf("puf: need ≥ 8 calibration cycles, got %d", o.CalibrationCycles)
	}

	cfg := Config{Trials: o.Trials}

	var baseline *Baseline
	fps := make([]Fingerprint, 0, o.CalibrationCycles)
	for i := 0; i < o.CalibrationCycles; i++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		m, err := Measure(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("puf: calibration %d: %w", i, err)
		}
		fp := QuantizeV3(m, baseline)
		if i == 0 {
			bl := NewBaseline(m)
			baseline = &bl
		}
		fps = append(fps, fp)
		if i+1 < o.CalibrationCycles && o.Cooldown > 0 {
			timer := time.NewTimer(o.Cooldown)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if baseline == nil {
		return nil, nil, errors.New("puf: calibration produced no baseline")
	}

	indices := SelectReliableBits(fps, o.MaxBER)
	if len(indices) < HelperBits {
		return nil, nil, fmt.Errorf(
			"puf: only %d reliable bits ≤ BER %.2f%% found, need %d",
			len(indices), o.MaxBER*100, HelperBits,
		)
	}

	K, hd, err := Enroll(fps[0], indices)
	if err != nil {
		return nil, nil, fmt.Errorf("puf: enroll: %w", err)
	}
	// Zero K as soon as we no longer need it.
	_, pub, err := DeriveEd25519(K)
	if err != nil {
		for i := range K {
			K[i] = 0
		}
		return nil, nil, fmt.Errorf("puf: derive ed25519: %w", err)
	}
	for i := range K {
		K[i] = 0
	}

	state := &KeyState{
		Version:           FuzzyKeyVersion,
		Helper:            *hd,
		Baseline:          *baseline,
		DerivedPub:        append([]byte(nil), pub...),
		EnrolledAt:        time.Now().UTC(),
		AgentVersion:      agentVersion,
		CalibrationCycles: o.CalibrationCycles,
		MaxBER:            o.MaxBER,
		ReliablePool:      len(indices),
	}

	pb := &agentpb.PufKeyEnrollment{
		HostId:            hostID,
		HelperVersion:     uint32(hd.Version),
		SecretBits:        uint32(hd.SecretBits),
		MaskBits:          uint32(hd.MaskBits),
		Indices:           toUint32s(hd.Indices),
		Mask:              append([]byte(nil), hd.Mask...),
		Commitment:        append([]byte(nil), hd.Commitment...),
		DerivedPubkey:     append([]byte(nil), pub...),
		CalibrationCycles: uint32(o.CalibrationCycles),
		MaxBer:            o.MaxBER,
		ReliablePool:      uint32(len(indices)),
		EnrolledAtMs:      time.Now().UnixMilli(),
		AgentVersion:      agentVersion,
	}
	return state, pb, nil
}

// ProveKey runs a single proof-of-possession cycle against a stored
// KeyState. It takes a fresh measurement, reproduces K from the
// helper, re-derives the Ed25519 private key, signs a random
// agent-chosen nonce + timestamp, and returns the resulting
// PufKeyProof protobuf. The private key is zeroed before return.
//
// Returns an error if the fresh measurement fails Reproduce — that
// normally means the silicon changed (migration, clone, tamper) and
// the caller should surface it as a TAMPER-equivalent verdict instead
// of a simple proof failure.
func ProveKey(
	ctx context.Context,
	hostID, agentVersion string,
	state *KeyState,
) (*agentpb.PufKeyProof, error) {
	if state == nil {
		return nil, errors.New("puf: prove on nil state")
	}
	_ = ctx

	cfg := Config{Trials: DefaultTrials}
	m, err := Measure(cfg)
	if err != nil {
		return nil, fmt.Errorf("puf: measure: %w", err)
	}
	// Use the *same* baseline that was captured at enrolment.
	// QuantizeV3's residual-gray bits are defined relative to it, so
	// feeding a different baseline here would silently shift every
	// residual bit and make reproduction fail even on matching
	// silicon.
	bl := state.Baseline
	fp := QuantizeV3(m, &bl)

	K, err := Reproduce(fp, &state.Helper)
	if err != nil {
		return nil, fmt.Errorf("puf: reproduce: %w", err)
	}
	priv, pub, err := DeriveEd25519(K)
	// Drop K as soon as the keypair is in hand.
	for i := range K {
		K[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("puf: derive ed25519: %w", err)
	}
	// Defence-in-depth: confirm the pub we just derived still matches
	// the one the server is holding. Mismatch here means the enrolment
	// blob on disk has been tampered with.
	if !bytesEqual(pub, state.DerivedPub) {
		// Zero the private key before returning.
		for i := range priv {
			priv[i] = 0
		}
		return nil, errors.New("puf: derived pubkey diverged from enrolled value")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		for i := range priv {
			priv[i] = 0
		}
		return nil, fmt.Errorf("puf: nonce: %w", err)
	}
	generatedAtMs := time.Now().UnixMilli()
	msg := ProofMessage(hostID, nonce, generatedAtMs)
	sig := ed25519.Sign(priv, msg)
	for i := range priv {
		priv[i] = 0
	}

	return &agentpb.PufKeyProof{
		HostId:        hostID,
		Nonce:         nonce,
		GeneratedAtMs: generatedAtMs,
		Signature:     sig,
		AgentVersion:  agentVersion,
	}, nil
}

// KeySupported reports whether this platform can run W5b. Currently
// matches Supported() but kept separate so we can tighten the bar for
// key derivation later (e.g. require ≥ 4 cores) without affecting the
// z-score attestation flow.
func KeySupported() bool {
	return runtime.GOOS == "linux" && runtime.NumCPU() >= 2
}

// DerivedPubkeyHex returns the stored public key as lowercase hex —
// the same encoding the server stores it in — for display in agent
// logs.
func (s *KeyState) DerivedPubkeyHex() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.DerivedPub)
}

// toUint32s widens a []int of bit indices to []uint32 for the wire
// protocol. Caller has already bounded the indices to the QuantizeV3
// output length, which is well below 2^32.
func toUint32s(in []int) []uint32 {
	out := make([]uint32, len(in))
	for i, v := range in {
		out[i] = uint32(v)
	}
	return out
}

// bytesEqual wraps crypto/subtle.ConstantTimeCompare for clarity.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
