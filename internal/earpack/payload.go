package earpack

import (
	"fmt"

	"github.com/963causal/agent/internal/siliconcert"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"
)

// EARVersion is the semantic version of the CBOR payload map inside COSE.
const EARVersion = "0.1.0"

// ScopeADR023Default is the contractual scope line for insurance export (abbrev).
const ScopeADR023Default = "ADR-007 continuity + ADR-023 EAR export; not a warranty of overall security"

// Payload is the CBOR-serialisable body inside COSE_Sign1.Payload.
type Payload struct {
	V      string `cbor:"v"`                 // EARVersion
	Scope  string `cbor:"scope"`             // legal / technical scope line
	IssMs  int64  `cbor:"iss_ms"`            // export issue time (informational)
	ScVer  string `cbor:"sc_ver"`            // siliconcert schema tag
	ScJSON []byte `cbor:"sc_json"`           // full siliconcert JSON (self-contained)
	ScSHA3 []byte `cbor:"sc_sha3,omitempty"` // SHA3-256(sc_json); duplicate for quick lookup
}

// MarshalPayloadCBOR builds the canonical CBOR payload from a Silicon Certificate.
func MarshalPayloadCBOR(cert *siliconcert.V1, scope string, issuedMs int64) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("earpack: nil silicon certificate")
	}
	raw, err := cert.MarshalJSONBytes()
	if err != nil {
		return nil, err
	}
	if scope == "" {
		scope = ScopeADR023Default
	}
	sum := sha3.Sum256(raw)
	p := Payload{
		V:      EARVersion,
		Scope:  scope,
		IssMs:  issuedMs,
		ScVer:  cert.SchemaVersion,
		ScJSON: raw,
		ScSHA3: sum[:],
	}
	return cbor.Marshal(p)
}

// UnmarshalPayloadCBOR decodes the payload bytes after COSE verification.
func UnmarshalPayloadCBOR(b []byte) (*Payload, error) {
	var p Payload
	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.V == "" || len(p.ScJSON) == 0 {
		return nil, fmt.Errorf("earpack: invalid payload")
	}
	return &p, nil
}
