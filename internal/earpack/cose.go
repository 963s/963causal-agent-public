package earpack

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/veraison/go-cose"
)

// SignCOSE1Sign1 produces a COSE_Sign1_Tagged (CBOR) object: EdDSA over the
// EAR payload. externalAAD is usually nil; use the same value at verify time.
func SignCOSE1Sign1(payload []byte, priv ed25519.PrivateKey, kid []byte, externalAAD []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("earpack: empty payload")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("earpack: ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
	}
	if len(kid) > 0 {
		msg.Headers.Unprotected = cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: kid,
		}
	}
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, externalAAD, signer); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

// VerifyCOSE1Sign1 checks the signature and returns the payload.
func VerifyCOSE1Sign1(coseBytes []byte, pub ed25519.PublicKey, externalAAD []byte) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("earpack: ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return nil, err
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		return nil, err
	}
	if err := msg.Verify(externalAAD, verifier); err != nil {
		return nil, err
	}
	if len(msg.Payload) == 0 {
		return nil, fmt.Errorf("earpack: empty payload after verify")
	}
	return msg.Payload, nil
}

// ExportKID returns an 8-byte key identifier from the export public key
// (hash prefix — not a raw PUF value; see BSL ADR-023).
func ExportKID(pub ed25519.PublicKey) []byte {
	if len(pub) != ed25519.PublicKeySize {
		return nil
	}
	h := sha256.Sum256(pub)
	return h[:8]
}

// ReadEd25519PrivateFile loads a 32-byte seed or 64-byte expanded private key
// from a file (raw). For hex, use ReadEd25519PrivateHex.
func ReadEd25519PrivateFile(r io.Reader) (ed25519.PrivateKey, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(b) == 32 {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) == ed25519.SeedSize+ed25519.PublicKeySize {
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("earpack: want 32-byte seed or %d-byte private key, got %d", ed25519.SeedSize+ed25519.PublicKeySize, len(b))
}
