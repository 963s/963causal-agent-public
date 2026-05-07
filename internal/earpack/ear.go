package earpack

import (
	"crypto/ed25519"
	"time"

	"github.com/963causal/agent/internal/siliconcert"
)

// SignDocument builds the EAR CBOR payload from a Silicon Certificate and
// returns a complete COSE_Sign1_Tagged binary blob.
func SignDocument(cert *siliconcert.V1, exportPriv ed25519.PrivateKey, scope string) ([]byte, error) {
	now := time.Now().UnixMilli()
	if scope == "" {
		scope = ScopeADR023Default
	}
	pl, err := MarshalPayloadCBOR(cert, scope, now)
	if err != nil {
		return nil, err
	}
	kid := ExportKID(exportPriv.Public().(ed25519.PublicKey))
	return SignCOSE1Sign1(pl, exportPriv, kid, nil)
}

// VerifyDocument verifies a COSE blob and returns the inner EAR payload + parsed cert.
func VerifyDocument(coseBytes []byte, exportPub ed25519.PublicKey) (*Payload, *siliconcert.V1, error) {
	raw, err := VerifyCOSE1Sign1(coseBytes, exportPub, nil)
	if err != nil {
		return nil, nil, err
	}
	p, err := UnmarshalPayloadCBOR(raw)
	if err != nil {
		return nil, nil, err
	}
	cert, err := siliconcert.ParseV1(p.ScJSON)
	if err != nil {
		return p, nil, err
	}
	return p, cert, nil
}
