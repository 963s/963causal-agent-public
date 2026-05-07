package daq

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Domain is the string prefix SHA3-256-mixed into every DAQ signing
// input. Any signature on a message that does NOT start with this tag
// is cryptographically incompatible with a DAQ attestation, regardless
// of key reuse. Bumping Domain is how we would hard-fork the protocol
// if the canonical layout ever had to change.
const Domain = "963causal-DAQ-V1"

// Mode is a one-byte enum baked into the signing input so that a
// signature produced in ParallelMode cannot accidentally be reused in
// SequentialMode (or vice-versa) even on the same operation.
type Mode byte

const (
	ModeParallel   Mode = 0x00
	ModeSequential Mode = 0x01
)

func (m Mode) String() string {
	switch m {
	case ModeParallel:
		return "parallel"
	case ModeSequential:
		return "sequential"
	default:
		return fmt.Sprintf("mode(0x%02x)", byte(m))
	}
}

// Request carries everything the witnesses need to evaluate, plus the
// agent's proof that it really initiated the call. It is the unit
// shipped over HTTP from the agent to each witness.
//
// Invariants enforced at every consumer:
//
//   • OpID is opaque but length-prefixed in the signed input so an
//     attacker cannot confuse "op_id=AB, hash=CD..." with
//     "op_id=A, hash=BCD...".
//
//   • OpHash is always 32 bytes (sha3-256 of whatever the operation
//     payload is). Agents that don't want to disclose the payload can
//     simply commit to it and reveal later.
//
//   • AgentPubkey is the W5b PUF-derived Ed25519 key. AgentSignature
//     covers canonicalRequestBytes() below and binds the agent as the
//     genuine originator — witnesses check this *before* signing.
//
//   • DrandRound / DrandSignature anchor freshness. Witnesses re-fetch
//     round `DrandRound` from their own drand view and reject the
//     request if signatures disagree or if the round is too far from
//     their local "now".
type Request struct {
	OpID            string
	OpHash          []byte // 32B
	AgentPubkey     []byte // 32B Ed25519
	AgentSignature  []byte // 64B
	DrandChain      string
	DrandRound      uint64
	DrandSignature  []byte // 48B (BLS G1 from fastnet)
	RequestedAtMs   int64
}

// WitnessSignature is what each witness returns. Pubkey is the
// witness's BDN public key (96 B), not its Ed25519 identity.
type WitnessSignature struct {
	WitnessIndex int    // position in the roster
	Pubkey       []byte // 96B BDN G2
	Signature    []byte // 48B BDN G1
}

// Ticket is the aggregated proof the agent carries into any operation
// that is gated on DAQ consensus. In ParallelMode the signature slice
// has length 1 (the BDN aggregate) and Mask carries the participation
// bitmask. In SequentialMode the signature slice preserves the per-
// witness order and Mask is the expansion of WitnessIndex values.
type Ticket struct {
	Request      Request
	Mode         Mode
	Threshold    int               // k
	RosterSize   int               // n
	Witnesses    []WitnessSignature // in sequential mode: ordered chain
	AggSignature []byte             // non-empty only in parallel mode
	AggMask      []byte             // non-empty only in parallel mode
	CreatedAtMs  int64
}

// CanonicalRequestBytes returns the bytes the AGENT signs with its
// Ed25519 key to prove it originated the request. Shape:
//
//   DOMAIN || "agent-req" || op_id_len (u16 BE) || op_id
//          || op_hash (32) || chain_len (u16 BE) || chain
//          || drand_round (u64 BE) || drand_sig (48)
//          || requested_at_ms (i64 BE)
//
// Does NOT include AgentPubkey because Ed25519 verification takes the
// key as a separate argument; including the pubkey in the signed
// bytes would be redundant and make canonicalisation fragile.
func CanonicalRequestBytes(r *Request) ([]byte, error) {
	if r == nil {
		return nil, errors.New("daq: canonicalise nil request")
	}
	if len(r.OpHash) != 32 {
		return nil, fmt.Errorf("daq: op_hash must be 32B, got %d", len(r.OpHash))
	}
	if len(r.DrandSignature) != 48 {
		return nil, fmt.Errorf("daq: drand sig must be 48B, got %d", len(r.DrandSignature))
	}
	if len(r.OpID) > 0xFFFF {
		return nil, fmt.Errorf("daq: op_id too long (%d > 65535)", len(r.OpID))
	}
	if len(r.DrandChain) > 0xFFFF {
		return nil, fmt.Errorf("daq: drand_chain too long (%d > 65535)", len(r.DrandChain))
	}
	var buf []byte
	buf = append(buf, Domain...)
	buf = append(buf, "|agent-req|"...)
	buf = appendU16(buf, uint16(len(r.OpID)))
	buf = append(buf, r.OpID...)
	buf = append(buf, r.OpHash...)
	buf = appendU16(buf, uint16(len(r.DrandChain)))
	buf = append(buf, r.DrandChain...)
	buf = appendU64(buf, r.DrandRound)
	buf = append(buf, r.DrandSignature...)
	buf = appendI64(buf, r.RequestedAtMs)
	return buf, nil
}

// WitnessInput returns the exact bytes each witness feeds into
// BDN.Sign. In parallel mode the layout is:
//
//   SHA3-256(DOMAIN || "witness" || mode || op_id_len || op_id
//            || op_hash || chain || drand_round || drand_sig
//            || agent_pubkey)
//
// In sequential mode the input additionally carries the position
// index and the previous witness's signature:
//
//   SHA3-256(... parallel prefix ... || seq_index (u16 BE) || prev_sig (48))
//
// We pre-hash down to 32 bytes before handing to BDN so that the
// length of the input is bounded and the BLS hash-to-curve step has
// a well-defined upstream. The DOMAIN string is included inside the
// hash *and* used as BDN's DST implicitly through the pairing suite,
// giving double protection against cross-protocol reuse.
func WitnessInput(r *Request, mode Mode, seqIndex int, prevSig []byte) ([]byte, error) {
	if r == nil {
		return nil, errors.New("daq: witness input for nil request")
	}
	if len(r.OpHash) != 32 {
		return nil, fmt.Errorf("daq: op_hash must be 32B, got %d", len(r.OpHash))
	}
	if len(r.DrandSignature) != 48 {
		return nil, fmt.Errorf("daq: drand sig must be 48B, got %d", len(r.DrandSignature))
	}
	if len(r.AgentPubkey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("daq: agent pubkey must be %dB, got %d",
			ed25519.PublicKeySize, len(r.AgentPubkey))
	}
	if mode == ModeSequential {
		if seqIndex < 0 || seqIndex > 0xFFFF {
			return nil, fmt.Errorf("daq: seq_index out of range: %d", seqIndex)
		}
		if seqIndex > 0 && len(prevSig) != 48 {
			return nil, fmt.Errorf("daq: prev_sig must be 48B for seq_index=%d", seqIndex)
		}
	}

	h := sha3.New256()
	h.Write([]byte(Domain))
	h.Write([]byte("|witness|"))
	h.Write([]byte{byte(mode)})
	writeU16(h, uint16(len(r.OpID)))
	h.Write([]byte(r.OpID))
	h.Write(r.OpHash)
	writeU16(h, uint16(len(r.DrandChain)))
	h.Write([]byte(r.DrandChain))
	writeU64(h, r.DrandRound)
	h.Write(r.DrandSignature)
	h.Write(r.AgentPubkey)
	if mode == ModeSequential {
		writeU16(h, uint16(seqIndex))
		if seqIndex > 0 {
			h.Write(prevSig)
		}
	}
	return h.Sum(nil), nil
}

// VerifyAgentSignature re-checks the Ed25519 signature the agent
// supplied in the request. Witnesses call this before doing any
// expensive BDN work; the server calls it again on ticket ingest.
func VerifyAgentSignature(r *Request) error {
	if len(r.AgentPubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("daq: agent pubkey wrong size: %d", len(r.AgentPubkey))
	}
	if len(r.AgentSignature) != ed25519.SignatureSize {
		return fmt.Errorf("daq: agent signature wrong size: %d", len(r.AgentSignature))
	}
	msg, err := CanonicalRequestBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(r.AgentPubkey), msg, r.AgentSignature) {
		return errors.New("daq: agent signature invalid")
	}
	return nil
}

// HashOperationPayload is a convenience for callers that want a
// canonical way to produce OpHash from raw bytes. Using SHA3-256
// mirrors the rest of the 963causal stack.
func HashOperationPayload(payload []byte) []byte {
	h := sha3.Sum256(payload)
	return h[:]
}

func appendU16(b []byte, v uint16) []byte {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	return append(b, x[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

func appendI64(b []byte, v int64) []byte {
	return appendU64(b, uint64(v))
}

type byteSink interface{ Write([]byte) (int, error) }

func writeU16(w byteSink, v uint16) {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	_, _ = w.Write(x[:])
}

func writeU64(w byteSink, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	_, _ = w.Write(x[:])
}
