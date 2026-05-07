// Package rebirth — the Phoenix protocol.
//
// Answers the "Identity Extinction" critique: when the silicon
// bound to K_PAL dies (hardware failure, live-migration to
// different physical host, AWS / Oracle recycling), the PUF
// identity dies with it. 963causal's design is to NOT back up
// K_PAL because doing so defeats the PUF — but a production
// system that treats every hardware failure as "identity
// deleted, start from t=0" cannot claim 99.999 % availability.
//
// The resolution is a scope split that the pre-W15 BSL conflated:
//
//   HARDWARE IDENTITY (H) — PUF-bound, per-physical-machine,
//                           dies with the silicon (as designed).
//   SERVICE IDENTITY (S)  — logical, long-lived, distributed
//                           across DAQ witnesses via W11 LBS
//                           (threshold BLS). Survives any number
//                           of hardware failures.
//
// The binding H ↔ S is itself an attested fact, not a
// cryptographic seal. When H₁ dies and H₂ replaces it, the
// witnesses issue a REBIRTH ATTESTATION that transfers the S
// binding to H₂'s fresh PUF identity. Every rebirth becomes an
// auditable event in the LineageLog; downstream consumers who
// cached P_S (S's public key) never have to rotate, because P_S
// is a witness-held LBS pubkey, not an H-derived key.
//
// Security claim:
//
//   An adversary who wants to claim service S on hardware H'
//   they control must:
//
//     (a) convince ≥ k witnesses that H' is the legitimate
//         replacement for S, which requires a valid rebirth
//         request signed by the operator's own key (the same
//         key that authenticates admin sessions today), AND
//
//     (b) do so within a cool-down period configured per
//         service. During the cool-down, the outgoing binding
//         remains active, so an attacker who catches the
//         window cannot silently hijack S.
//
// An adversary who compromises:
//
//   * H₁ silicon and the operator key simultaneously → wins
//     immediately, but has to publish the rebirth in the
//     LineageLog, which is append-only and externally mirrored.
//   * Only H₁ silicon → cannot rebirth (no operator key).
//   * Only operator key → cannot rebirth without witness
//     attestations, which will refuse if H₁ is still proving
//     liveness via W5b.
//
// This is NOT a new security primitive. It is a careful
// re-composition of what W5b (PUF) + W6 (DAQ) + W11 (LBS) +
// W14 roster-chain already ship. The Phoenix protocol is the
// missing piece that turns the stack from "brittle against
// hardware failure" to "resilient, with an auditable
// continuity ledger".
package rebirth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
)

// ErrRebirth is the root error class the Phoenix protocol emits.
// Wrapped errors carry the specific reason so operators can tell
// "cool-down not elapsed" apart from "below threshold" etc.
var ErrRebirth = errors.New("rebirth: protocol error")

// Request is the structured claim a new host submits to DAQ
// witnesses: "I am the replacement for service S, here is my
// new PUF-derived pubkey, here are the M-OF-N operator
// signatures authorising the rebirth (ADR-018), and here is
// the public certificate of the old host so witnesses can
// sanity-check the lineage."
//
// Multi-operator design (ADR-018): a single operator key is a
// single point of failure for the whole Phoenix protocol. A
// request now carries ≥ M signatures from a PINNED SET of
// operator pubkeys. Witnesses verify every signature and
// reject if the count is below M or if any signer is not
// pinned. Compromise of ONE operator key is therefore
// insufficient to hijack a service.
//
// The byte shape is deterministic under Canonical() so
// signatures are reproducible; any byte-level tamper fails
// every tag simultaneously.
type Request struct {
	ServiceID           string                // opaque operator-chosen identity; matches the LBS service pubkey stored at witnesses
	NewHostPubkey       []byte                // 32-byte Ed25519 of the fresh PUF-derived key on the replacement host
	OldHostPubkey       []byte                // 32-byte Ed25519 of the deceased host; empty iff the operator declares this a "graveyard" rebirth (no previous host)
	OperatorSignatures  []OperatorSignature   // ≥ M distinct operators signing from a pinned set; empty fallback to legacy single-op path below
	RequestedAtMs       int64
	CoolDownMs          int64 // operator-specified window before execution can complete (minimum enforced by witnesses)

	// Legacy single-operator fields. Retained for backward
	// compatibility with the ADR-014 PoC callers; if
	// OperatorSignatures is non-empty these are ignored.
	// New callers SHOULD always use OperatorSignatures.
	OperatorPubkey    []byte
	OperatorSignature []byte
}

// OperatorSignature is one entry in a multi-operator request.
// Pubkey MUST be in the witness's pinned set; Signature is
// Ed25519 over Canonical() (same bytes as the legacy single-
// op mode).
type OperatorSignature struct {
	Pubkey    []byte
	Signature []byte
}

// Canonical emits the deterministic serialisation operators
// sign and witnesses re-serialise to verify. Every byte of the
// struct is length-prefixed except the fixed-size pubkeys and
// timestamps.
//
// IMPORTANT: the canonical bytes deliberately EXCLUDE the
// operator signatures themselves (obviously — we'd sign our
// own signature) AND the legacy OperatorPubkey field (for
// wire compatibility — the pubkey is carried in the signature
// entries or the legacy single-op field instead). The
// ServiceID + NewHostPubkey + OldHostPubkey + timing fields
// are all covered; any tamper flips every signature
// simultaneously.
func (r Request) Canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString("963causal-REBIRTH-REQUEST-V2\x00")
	writeWithLen(&buf, []byte(r.ServiceID))
	writeWithLen(&buf, r.NewHostPubkey)
	writeWithLen(&buf, r.OldHostPubkey)
	writeI64(&buf, r.RequestedAtMs)
	writeI64(&buf, r.CoolDownMs)
	return buf.Bytes()
}

// SealRequest is the legacy single-operator helper retained
// for backward compatibility with the W15 PoC callers. New
// callers SHOULD use SealRequestMultiOp. This one still works
// but produces a Request with only the legacy
// OperatorPubkey/OperatorSignature fields populated, which
// Verify accepts when the deployment's policy allows M = 1.
func SealRequest(
	serviceID string,
	newHostPub ed25519.PublicKey,
	oldHostPub ed25519.PublicKey,
	operatorPriv ed25519.PrivateKey,
	coolDown time.Duration,
) (*Request, error) {
	return SealRequestMultiOp(serviceID, newHostPub, oldHostPub,
		[]ed25519.PrivateKey{operatorPriv}, coolDown)
}

// SealRequestMultiOp is the M-of-N operator-side helper. Each
// operator private key signs the SAME Canonical() bytes; the
// resulting signatures are collected into OperatorSignatures.
// Witnesses verify ≥ M distinct signatures and check each
// signer against a PINNED OPERATOR SET.
//
// At least one private key must be supplied. If exactly one is
// supplied, the legacy single-op fields are ALSO populated so
// legacy verifiers (that still look at OperatorPubkey /
// OperatorSignature) continue to accept the request.
func SealRequestMultiOp(
	serviceID string,
	newHostPub ed25519.PublicKey,
	oldHostPub ed25519.PublicKey,
	operatorPrivs []ed25519.PrivateKey,
	coolDown time.Duration,
) (*Request, error) {
	if serviceID == "" {
		return nil, fmt.Errorf("%w: empty service_id", ErrRebirth)
	}
	if len(newHostPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: new host pubkey size %d, expected %d",
			ErrRebirth, len(newHostPub), ed25519.PublicKeySize)
	}
	if len(operatorPrivs) == 0 {
		return nil, fmt.Errorf("%w: need ≥ 1 operator private key", ErrRebirth)
	}
	for i, p := range operatorPrivs {
		if len(p) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: operator priv[%d] wrong size", ErrRebirth, i)
		}
	}
	req := Request{
		ServiceID:     serviceID,
		NewHostPubkey: append([]byte(nil), newHostPub...),
		OldHostPubkey: append([]byte(nil), oldHostPub...),
		RequestedAtMs: time.Now().UnixMilli(),
		CoolDownMs:    coolDown.Milliseconds(),
	}
	canon := req.Canonical()
	req.OperatorSignatures = make([]OperatorSignature, len(operatorPrivs))
	for i, priv := range operatorPrivs {
		pub := priv.Public().(ed25519.PublicKey)
		req.OperatorSignatures[i] = OperatorSignature{
			Pubkey:    append([]byte(nil), pub...),
			Signature: ed25519.Sign(priv, canon),
		}
	}
	// Populate legacy fields when exactly one operator signed.
	// Lets the W15-era tests keep working without being rewritten.
	if len(operatorPrivs) == 1 {
		req.OperatorPubkey = req.OperatorSignatures[0].Pubkey
		req.OperatorSignature = req.OperatorSignatures[0].Signature
	}
	return &req, nil
}

// VerifyOperator is the first check every witness runs: is
// this request signed by ≥ M distinct operators from the
// pinned set? Legacy single-operator requests (no
// OperatorSignatures populated) still work when
// opThreshold == 1, so W15 callers keep their behaviour.
//
// `pinnedOperators` is the list of pubkeys the deployment
// trusts (ADR-018: typically 3–7 principals stored in
// geographically-separated HSMs, set by BSL update).
// `opThreshold` is the M-of-N minimum; opThreshold = 1
// preserves the legacy single-op semantics.
func VerifyOperator(req *Request, pinnedOperators [][]byte, opThreshold int) error {
	if req == nil {
		return fmt.Errorf("%w: nil request", ErrRebirth)
	}
	if opThreshold < 1 {
		return fmt.Errorf("%w: opThreshold < 1", ErrRebirth)
	}
	canon := req.Canonical()

	// Collect the (pubkey, signature) pairs from whichever
	// field the caller populated — new callers use
	// OperatorSignatures, W15 callers stuck on the legacy
	// single-op path.
	sigs := req.OperatorSignatures
	if len(sigs) == 0 {
		if len(req.OperatorPubkey) == ed25519.PublicKeySize &&
			len(req.OperatorSignature) == ed25519.SignatureSize {
			sigs = []OperatorSignature{{
				Pubkey:    req.OperatorPubkey,
				Signature: req.OperatorSignature,
			}}
		}
	}
	if len(sigs) < opThreshold {
		return fmt.Errorf("%w: got %d operator signatures, need ≥ %d",
			ErrRebirth, len(sigs), opThreshold)
	}

	seen := make(map[string]bool, len(sigs))
	validCount := 0
	for i, s := range sigs {
		if len(s.Pubkey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: operator[%d] pubkey wrong size", ErrRebirth, i)
		}
		if len(s.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("%w: operator[%d] sig wrong size", ErrRebirth, i)
		}
		if seen[string(s.Pubkey)] {
			return fmt.Errorf("%w: operator[%d] duplicate pubkey", ErrRebirth, i)
		}
		seen[string(s.Pubkey)] = true
		if !anyEqual(pinnedOperators, s.Pubkey) {
			return fmt.Errorf("%w: operator[%d] pubkey %x… not in pinned set",
				ErrRebirth, i, s.Pubkey[:8])
		}
		if !ed25519.Verify(s.Pubkey, canon, s.Signature) {
			return fmt.Errorf("%w: operator[%d] signature invalid", ErrRebirth, i)
		}
		validCount++
	}
	if validCount < opThreshold {
		return fmt.Errorf("%w: only %d valid operator sigs, need ≥ %d",
			ErrRebirth, validCount, opThreshold)
	}
	return nil
}

// Attestation is one witness's endorsement of a Rebirth Request.
// Carries the witness's pubkey (for the LineageLog) and an
// Ed25519 signature over the canonical request bytes + the
// witness-observed current time. The time binding prevents a
// stale attestation from being reused in a future rebirth of
// the same service.
type Attestation struct {
	WitnessIndex int
	WitnessPub   []byte
	ObservedAtMs int64
	Signature    []byte
}

// attestationMessage is the bytes a witness signs; it binds the
// request hash + the witness's own observation time + the
// service id, so an attestation is unambiguous about WHICH
// request it endorses.
func attestationMessage(req *Request, observedAtMs int64) []byte {
	h := sha3.New256()
	h.Write([]byte("963causal-REBIRTH-ATTEST-V1\x00"))
	h.Write(req.Canonical())
	writeI64(h, observedAtMs)
	return h.Sum(nil)
}

// Attest is the witness-side helper: verify the operator,
// verify the cool-down, and emit an Attestation if everything
// checks out.
//
// `minCoolDown` is the witness's OWN floor; even if the operator
// requested a cool-down of zero, the witness enforces its own
// minimum to prevent a compromised operator key from
// instant-hijacking S.
func Attest(
	req *Request,
	pinnedOperators [][]byte,
	opThreshold int,
	witnessIndex int,
	witnessPriv ed25519.PrivateKey,
	nowMs int64,
	minCoolDown time.Duration,
) (*Attestation, error) {
	if err := VerifyOperator(req, pinnedOperators, opThreshold); err != nil {
		return nil, err
	}
	if req.CoolDownMs < minCoolDown.Milliseconds() {
		return nil, fmt.Errorf("%w: cool-down %d ms below witness floor %d ms",
			ErrRebirth, req.CoolDownMs, minCoolDown.Milliseconds())
	}
	if nowMs < req.RequestedAtMs {
		return nil, fmt.Errorf("%w: request from the future (request=%d, now=%d)",
			ErrRebirth, req.RequestedAtMs, nowMs)
	}
	// A request that is much older than the cool-down is
	// probably a replay; refuse. We use 5× the cool-down as the
	// absolute staleness bound.
	if nowMs > req.RequestedAtMs+5*req.CoolDownMs {
		return nil, fmt.Errorf("%w: request stale (age %d ms > 5×cool-down)",
			ErrRebirth, nowMs-req.RequestedAtMs)
	}
	pub := witnessPriv.Public().(ed25519.PublicKey)
	a := Attestation{
		WitnessIndex: witnessIndex,
		WitnessPub:   append([]byte(nil), pub...),
		ObservedAtMs: nowMs,
	}
	a.Signature = ed25519.Sign(witnessPriv, attestationMessage(req, nowMs))
	return &a, nil
}

// LineageRecord is the append-only ledger entry a successful
// rebirth produces. Every consumer of the service identity that
// needs to see the audit trail reads these; the append-only
// property must be enforced by the storage layer (the ADR-013
// roster chain does the same thing for rosters).
type LineageRecord struct {
	Request      Request
	Attestations []Attestation
	ExecutedAtMs int64
}

// Execute is the control-plane-side operation that turns k
// attestations into a LineageRecord. It enforces:
//
//   1. Every attestation verifies against Canonical(req).
//   2. No two attestations share the same WitnessIndex.
//   3. Every attestation's ObservedAtMs ≥ req.RequestedAtMs +
//      req.CoolDownMs (cool-down elapsed on EVERY witness).
//   4. The count is ≥ k (caller-supplied threshold).
//
// On success, the LineageRecord MUST be appended to the
// LineageLog before the control plane updates any "current
// host" mapping — if the append fails, the rebirth is aborted.
// The ordering is "log-first, commit-second" because an
// attacker who can write to the host-mapping table cannot
// retroactively add to the append-only log.
func Execute(
	req *Request,
	attestations []Attestation,
	threshold int,
	nowMs int64,
) (*LineageRecord, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrRebirth)
	}
	if threshold < 1 {
		return nil, fmt.Errorf("%w: threshold < 1", ErrRebirth)
	}
	if len(attestations) < threshold {
		return nil, fmt.Errorf("%w: %d attestations, need ≥ %d",
			ErrRebirth, len(attestations), threshold)
	}
	earliestExecute := req.RequestedAtMs + req.CoolDownMs
	if nowMs < earliestExecute {
		return nil, fmt.Errorf("%w: cool-down not elapsed (now=%d < earliest=%d)",
			ErrRebirth, nowMs, earliestExecute)
	}
	seen := make(map[int]bool, len(attestations))
	for i, a := range attestations {
		if seen[a.WitnessIndex] {
			return nil, fmt.Errorf("%w: attestation %d duplicates witness index %d",
				ErrRebirth, i, a.WitnessIndex)
		}
		seen[a.WitnessIndex] = true
		if len(a.WitnessPub) != ed25519.PublicKeySize || len(a.Signature) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: attestation %d wrong-size key/sig", ErrRebirth, i)
		}
		if a.ObservedAtMs < earliestExecute {
			return nil, fmt.Errorf("%w: attestation %d observed %d ms too early (cool-down not elapsed on witness)",
				ErrRebirth, i, earliestExecute-a.ObservedAtMs)
		}
		msg := attestationMessage(req, a.ObservedAtMs)
		if !ed25519.Verify(a.WitnessPub, msg, a.Signature) {
			return nil, fmt.Errorf("%w: attestation %d (witness index %d) signature invalid",
				ErrRebirth, i, a.WitnessIndex)
		}
	}
	return &LineageRecord{
		Request:      *req,
		Attestations: append([]Attestation(nil), attestations...),
		ExecutedAtMs: nowMs,
	}, nil
}

// VerifyLineage replays a list of LineageRecords to confirm
// the full continuity of a service identity. Parameters:
//
//   * pinnedOperators — the current trust set of operator pubkeys.
//   * opThreshold     — M-of-N operator-signature minimum (set
//                       to 1 for legacy single-op records).
//   * witnessThreshold — k-of-n witness-attestation minimum
//                       (unchanged from W15).
//
// Each record's OldHostPubkey MUST equal the previous record's
// NewHostPubkey (a "graveyard" rebirth with empty OldHostPubkey
// is valid only as the FIRST record — the initial enrolment of
// the service).
func VerifyLineage(records []LineageRecord, pinnedOperators [][]byte,
	opThreshold, witnessThreshold int,
) error {
	if len(records) == 0 {
		return fmt.Errorf("%w: empty lineage", ErrRebirth)
	}
	var expectedOld []byte
	for i, r := range records {
		if i == 0 {
			if len(r.Request.OldHostPubkey) != 0 {
				return fmt.Errorf("%w: record 0 has non-empty OldHostPubkey", ErrRebirth)
			}
		} else {
			if !bytes.Equal(expectedOld, r.Request.OldHostPubkey) {
				return fmt.Errorf("%w: record %d OldHostPubkey does not match previous NewHostPubkey",
					ErrRebirth, i)
			}
		}
		if err := VerifyOperator(&r.Request, pinnedOperators, opThreshold); err != nil {
			return fmt.Errorf("%w: record %d operator verify: %v", ErrRebirth, i, err)
		}
		if _, err := Execute(&r.Request, r.Attestations, witnessThreshold, r.ExecutedAtMs); err != nil {
			return fmt.Errorf("%w: record %d execute verify: %v", ErrRebirth, i, err)
		}
		expectedOld = r.Request.NewHostPubkey
	}
	return nil
}

// -----------------------------------------------------------------

func writeWithLen(w interface{ Write([]byte) (int, error) }, b []byte) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(len(b)))
	_, _ = w.Write(p[:])
	_, _ = w.Write(b)
}
func writeI64(w interface{ Write([]byte) (int, error) }, v int64) {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], uint64(v))
	_, _ = w.Write(p[:])
}
func anyEqual(set [][]byte, x []byte) bool {
	for _, s := range set {
		if bytes.Equal(s, x) {
			return true
		}
	}
	return false
}
