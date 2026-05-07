// Package siliconcert defines the portable "Silicon Certificate" bundle — the
// product-facing serialization of a verified DAQ ticket plus human-readable
// metadata aligned with ADR-007 (continuity-of-trust) and BSL §0 (runtime
// integrity thesis). Verification always delegates to daq.VerifyTicket.
package siliconcert

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/963causal/agent/internal/daq"
)

// SchemaV1 is the only supported JSON schema tag for new exports.
const SchemaV1 = "963causal.silicon-cert/v1"

// V1 is the first shipped wire format. It embeds a complete daq.Ticket so
// offline verifiers can re-run the same checks the agent ran at quorum time.
type V1 struct {
	SchemaVersion string `json:"schema_version"`
	// Kind is a stable product name for auditors (maps to "DDBC" narrative).
	Kind string `json:"kind"`

	IssuedAtUnixMs int64  `json:"issued_at_ms"`
	ScopeNote      string `json:"scope_note"`

	Workload struct {
		OpID          string `json:"op_id"`
		WorkloadHash  string `json:"workload_hash"` // hex(SHA3-256); same bytes as daq Request.OpHash
		WorkloadLabel string `json:"workload_label,omitempty"`
	} `json:"workload"`

	Timing struct {
		DrandRound    uint64 `json:"drand_round"`
		DrandChain    string `json:"drand_chain,omitempty"`
		DrandSigHex   string `json:"drand_signature"` // 48-byte G1 sig, lowercase hex
		CreatedAtMs   int64  `json:"ticket_created_at_ms,omitempty"`
		WitnessUnixMs []int64 `json:"witness_timestamps,omitempty"` // optional; filled when known
	} `json:"timestamp"`

	HardwareIdentity struct {
		// AgentPubkeyHex is the W5b-derived Ed25519 public key (32 B), hex.
		AgentPubkeyHex string `json:"agent_pubkey_hex"`
		Note           string `json:"note,omitempty"`
	} `json:"hardware_identity"`

	// Ticket is the full DAQ proof (agent sig + witness quorum + drand bind).
	Ticket daq.Ticket `json:"daq_ticket"`
}

// ScopeADR007 is the canonical scope string quoted in compliance docs.
const ScopeADR007 = "Continuity-of-trust per ADR-007: binds workload + silicon pubkey + drand round + witness quorum; does not attest firmware genesis."

// FromTicket builds a V1 bundle from an already-assembled DAQ ticket.
func FromTicket(t *daq.Ticket, workloadLabel string) (*V1, error) {
	if t == nil {
		return nil, errors.New("siliconcert: nil ticket")
	}
	if len(t.Request.OpHash) != 32 {
		return nil, fmt.Errorf("siliconcert: op_hash must be 32 B, got %d", len(t.Request.OpHash))
	}
	out := &V1{
		SchemaVersion: SchemaV1,
		Kind:          "silicon-certificate",
		IssuedAtUnixMs: time.Now().UnixMilli(),
		ScopeNote:      ScopeADR007,
	}
	out.Workload.OpID = t.Request.OpID
	out.Workload.WorkloadHash = hex.EncodeToString(t.Request.OpHash)
	out.Workload.WorkloadLabel = workloadLabel

	out.Timing.DrandRound = t.Request.DrandRound
	out.Timing.DrandChain = t.Request.DrandChain
	out.Timing.DrandSigHex = hex.EncodeToString(t.Request.DrandSignature)
	out.Timing.CreatedAtMs = t.CreatedAtMs

	out.HardwareIdentity.AgentPubkeyHex = hex.EncodeToString(t.Request.AgentPubkey)
	out.HardwareIdentity.Note = "W5b silicon-derived Ed25519 identity when enrolled; see BSL §11."

	out.Ticket = *t
	return out, nil
}

// Verify checks the embedded DAQ ticket against the witness roster (BDN
// public keys in roster index order).
func Verify(v *V1, roster []*daq.PublicKey) error {
	if v == nil {
		return errors.New("siliconcert: nil cert")
	}
	if v.SchemaVersion != SchemaV1 {
		return fmt.Errorf("siliconcert: unsupported schema %q", v.SchemaVersion)
	}
	return daq.VerifyTicket(&v.Ticket, roster)
}

// MarshalJSON is a convenience for stable logging / archival.
func (v *V1) MarshalJSONBytes() ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ParseV1 parses a Silicon Certificate JSON document.
func ParseV1(data []byte) (*V1, error) {
	var v V1
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	if v.SchemaVersion != SchemaV1 {
		return nil, fmt.Errorf("siliconcert: schema %q != %s", v.SchemaVersion, SchemaV1)
	}
	return &v, nil
}
