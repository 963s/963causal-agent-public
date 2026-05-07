package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CausalIDFromEd25519Pub derives the public Causal ID from the raw Ed25519 public key.
// It matches the control plane and web portal: SHA-256(pub), first 8 bytes as hex,
// formatted CID-963-XXXXXXXX-XXXXXXXX (uppercase hex).
func CausalIDFromEd25519Pub(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:8])
	u := strings.ToUpper(h)
	return "CID-963-" + u[:8] + "-" + u[8:]
}
