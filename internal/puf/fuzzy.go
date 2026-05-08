package puf

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// FuzzyKeyVersion is the protocol version stamped into helper data.
// Bump this if the bit-layout, code, or KDF change in a way that
// would invalidate previously-stored helpers — the server should then
// refuse Reproduce attempts that quote a version it does not
// understand, forcing a re-enrolment rather than silently deriving a
// wrong key.
const FuzzyKeyVersion uint8 = 1

// SecretBits is the length of the secret material extracted from the
// PUF, in bits. 128 was chosen because it is the smallest size that
// is both (a) widely accepted as collision-resistant under the
// generic birthday bound and (b) actually achievable on a 4-core
// Ampere Altra cloud VM with the V3 quantiser plus the two extra
// loop kinds (cmd/puf-ber, 50 cycles, 2026-04-17 — 275 bits passed
// the BER ≤ 2 % bar, comfortably above the 224 a Hamming(7,4)
// requires for 128 information bits).
const SecretBits = 128

// HelperBits is the length of the codeword-vs-PUF XOR mask the helper
// data carries, in bits. With Hamming(7,4) every 4 secret bits become
// 7 codeword bits, so the helper is exactly SecretBits/4*7.
const HelperBits = SecretBits / 4 * 7

// HelperData bundles everything the verifier needs to reproduce the
// secret from a fresh measurement. Indices is the list of bit
// positions in the V3 fingerprint that the enrolment selected as
// reliable; the first HelperBits of those become the actual PUF
// codeword space, and Mask is the codeword XOR PUF bits at those
// positions. Commitment is HKDF-SHA3-256(K, "963causal-puf-commit", 32)
// and lets the verifier confirm a successful recovery without
// touching the secret material.
//
// Helper data is *public*: it is shipped to the server at enrolment
// time and back to the agent whenever a Reproduce is needed. Because
// it is XOR'd against pseudo-random PUF bits, it leaks no information
// about the secret to anyone who does not also have the matching
// silicon.
type HelperData struct {
	Version    uint8  `json:"version"`
	Indices    []int  `json:"indices"`     // bit positions in the V3 fingerprint
	Mask       []byte `json:"mask"`        // codeword XOR PUF, len = (HelperBits+7)/8
	MaskBits   int    `json:"mask_bits"`   // exact bit count (HelperBits)
	SecretBits int    `json:"secret_bits"` // exact secret length (SecretBits)
	Commitment []byte `json:"commitment"`  // HKDF(K, "963causal-puf-commit", 32)
	CreatedAt  time.Time
}

// Enroll picks a fresh random SecretBits-bit secret K, derives the
// helper data so that any future measurement that produces the same
// reliable bits at the listed indices will recover K, and returns
// (K, helper). Caller must persist helper before discarding K — losing
// the helper means losing the key, and re-running Enroll on the same
// hardware will produce a *different* K.
//
// Indices must contain at least HelperBits entries; only the first
// HelperBits are used. The remaining entries are not part of the
// helper but should be retained by the caller as a "spare pool" — if
// some bit positions later turn out to drift, the enrolment can be
// refreshed by swapping the drifty index for one from the spare pool.
func Enroll(fp Fingerprint, indices []int) ([]byte, *HelperData, error) {
	if len(indices) < HelperBits {
		return nil, nil, fmt.Errorf("puf: enroll needs ≥ %d reliable bits, got %d",
			HelperBits, len(indices))
	}
	if fp.Length == 0 {
		return nil, nil, errors.New("puf: enroll on empty fingerprint")
	}
	K := make([]byte, SecretBits/8)
	if _, err := rand.Read(K); err != nil {
		return nil, nil, fmt.Errorf("puf: enroll randomness: %w", err)
	}
	codeword, encBits := EncodeHamming74(K, SecretBits)
	if encBits != HelperBits {
		return nil, nil, fmt.Errorf("puf: encoded length mismatch: got %d want %d",
			encBits, HelperBits)
	}

	pufBits := extractBitsAt(fp.Bits, indices[:HelperBits])
	mask := xorBytes(codeword, pufBits)

	commit, err := commitTo(K)
	if err != nil {
		return nil, nil, err
	}

	hd := &HelperData{
		Version:    FuzzyKeyVersion,
		Indices:    append([]int(nil), indices[:HelperBits]...),
		Mask:       mask,
		MaskBits:   HelperBits,
		SecretBits: SecretBits,
		Commitment: commit,
		CreatedAt:  time.Now().UTC(),
	}
	return K, hd, nil
}

// Reproduce inverts Enroll. Given a fresh measurement and a stored
// helper, it XORs the masked codeword back, runs the Hamming decoder
// to repair any bit-flips, and verifies the resulting K against the
// stored commitment. A non-nil error means either the helper is
// corrupt, the silicon does not match, or the BER on the selected
// bits exceeded what Hamming(7,4) can correct (more than one flip
// per 7-bit block).
func Reproduce(fp Fingerprint, hd *HelperData) ([]byte, error) {
	if hd == nil {
		return nil, errors.New("puf: reproduce with nil helper")
	}
	if hd.Version != FuzzyKeyVersion {
		return nil, fmt.Errorf("puf: unsupported helper version %d", hd.Version)
	}
	if hd.MaskBits != HelperBits || hd.SecretBits != SecretBits {
		return nil, fmt.Errorf("puf: helper sized for %d/%d, agent built for %d/%d",
			hd.SecretBits, hd.MaskBits, SecretBits, HelperBits)
	}
	if len(hd.Indices) != HelperBits {
		return nil, fmt.Errorf("puf: helper carries %d indices, expected %d",
			len(hd.Indices), HelperBits)
	}
	if fp.Length == 0 {
		return nil, errors.New("puf: reproduce on empty fingerprint")
	}

	pufBits := extractBitsAt(fp.Bits, hd.Indices)
	codewordNoisy := xorBytes(hd.Mask, pufBits)
	K, decBits := DecodeHamming74(codewordNoisy, HelperBits)
	if decBits != SecretBits {
		return nil, fmt.Errorf("puf: decoded %d secret bits, expected %d",
			decBits, SecretBits)
	}
	commit, err := commitTo(K)
	if err != nil {
		return nil, err
	}
	if !equalConstantTime(commit, hd.Commitment) {
		return nil, errors.New("puf: commitment mismatch — silicon differs or too many bit-errors")
	}
	return K, nil
}

// DeriveSubKey turns the raw PUF secret into a domain-separated 32-
// byte key suitable for symmetric encryption (e.g. ChaCha20-Poly1305
// inside Zero's secrets proxy). The PUF secret K is treated as IKM,
// the domain string serves as info, and a fixed salt scopes the
// derivation to the PAL fuzzy-extractor v1 protocol.
func DeriveSubKey(K []byte, domain string) ([]byte, error) {
	if len(K) == 0 {
		return nil, errors.New("puf: derive on empty K")
	}
	salt := []byte("963causal/puf/v1/fuzzy")
	h := hkdf.New(sha3.New256, K, salt, []byte(domain))
	out := make([]byte, 32)
	if _, err := h.Read(out); err != nil {
		return nil, fmt.Errorf("puf: hkdf: %w", err)
	}
	return out, nil
}

// CommitmentHex is a convenience wrapper that returns the helper's
// commitment as lowercase hex, matching the encoding the server-side
// Prisma layer stores it in. Avoids ad-hoc encoding sprinkles in the
// agent and the cmd tools.
func (h *HelperData) CommitmentHex() string {
	return hex.EncodeToString(h.Commitment)
}

// DeriveEd25519 turns the raw PUF secret into a deterministic Ed25519
// keypair. The seed is HKDF(K, salt, "ed25519-seed", 32) so changing
// the secret changes the keypair, and changing K changes the public
// half — letting the server detect a silicon swap by signature
// failure. Both halves can be re-derived from K alone, so the agent
// never needs to persist the private key.
//
// Returned (priv, pub) are the standard Ed25519 byte slices: priv is
// 64 bytes (seed || pub), pub is 32 bytes. Treat priv as a secret
// equal in sensitivity to K.
func DeriveEd25519(K []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(K) == 0 {
		return nil, nil, errors.New("puf: derive ed25519 from empty K")
	}
	salt := []byte("963causal/puf/v1/fuzzy")
	h := hkdf.New(sha3.New256, K, salt, []byte("ed25519-seed"))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := h.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("puf: hkdf seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// ProofMessage is the canonical bytes the agent signs to prove
// possession of K. Layout: host_id || nonce || generated_at_ms
// big-endian. Centralising the construction avoids subtle
// disagreements between the agent that signs and the server that
// verifies.
func ProofMessage(hostID string, nonce []byte, generatedAtMs int64) []byte {
	out := make([]byte, 0, len(hostID)+len(nonce)+8)
	out = append(out, []byte(hostID)...)
	out = append(out, nonce...)
	var ts [8]byte
	for i := 7; i >= 0; i-- {
		ts[i] = byte(generatedAtMs)
		generatedAtMs >>= 8
	}
	out = append(out, ts[:]...)
	return out
}

// commitTo derives the public commitment HKDF(K, salt, "commit", 32).
// Using HKDF rather than a bare hash gives clean domain separation
// between the commitment and any future sub-key derivations and
// matches the construction recommended in NIST SP 800-108r1 §5.
func commitTo(K []byte) ([]byte, error) {
	salt := []byte("963causal/puf/v1/fuzzy")
	h := hkdf.New(sha3.New256, K, salt, []byte("commit"))
	out := make([]byte, 32)
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// extractBitsAt reads the bits at the given indices (in their order)
// from a packed byte slice and returns a freshly-allocated packed
// slice carrying them sequentially. The output length is ceil(len /8)
// bytes, with bits laid out little-endian in each byte to match
// bitBuilder's packing convention.
func extractBitsAt(buf []byte, indices []int) []byte {
	out := make([]byte, (len(indices)+7)/8)
	for i, idx := range indices {
		if bitOf(buf, idx) != 0 {
			out[i>>3] |= 1 << uint(i&7)
		}
	}
	return out
}

// xorBytes returns a XOR b for slices of equal length.
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// equalConstantTime wraps crypto/subtle.ConstantTimeCompare for clarity.
func equalConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
