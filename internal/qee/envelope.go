package qee

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// ChaCha20-Poly1305 AEAD parameters. Re-used from internal/teb
// so every AEAD in the codebase stays on the same primitive and
// key-length conventions; operators auditing the memory-hygiene
// story have one curve to remember.
const (
	DataKeyBytes   = chacha20poly1305.KeySize   // 32
	DataNonceBytes = chacha20poly1305.NonceSize // 12
)

// ErrEnvelope is the envelope-level error wrapped on every
// failure so callers can `errors.Is` without string matching.
var ErrEnvelope = errors.New("qee/envelope: error")

// WitnessPubkey is a per-witness X25519 public key the sealer
// uses to encrypt one Shamir share. In production each witness
// generates its X25519 pair at roster-chain enrolment (ADR-013)
// and publishes the pub alongside its BDN pub. For PoC tests
// the caller constructs these directly.
type WitnessPubkey struct {
	Index  int     // slot in the roster
	Pubkey [32]byte
}

// SealedEnvelope is the public artefact a Seal produces. Carries
// the AEAD payload plus the two independent DEK wrappers:
//
//   * SiliconWrapped — DEK encrypted with the host's K_PAL-
//     derived symmetric key (fast path; one NaCl secretbox).
//     Opened by the SAME host that sealed.
//   * WitnessShares  — Shamir-split DEK, one NaCl box per
//     witness public key. Any k shares reconstruct the DEK;
//     fewer reveal nothing (information-theoretic security).
//
// Crucially, the DEK itself is NEVER stored. Both wrappers are
// irreversible without EITHER the sealing silicon OR ≥ k
// witness private keys. No "master key" exists.
type SealedEnvelope struct {
	// Data layer.
	DataNonce []byte // 12 bytes
	Data      []byte // AEAD-sealed plaintext

	// Silicon fast-path wrapper.
	SiliconWrap *SiliconWrap

	// Recovery path — k Shamir shares, each box-encrypted to
	// one witness's X25519 pub. Order must match the roster
	// slot indices carried inside each WitnessShare.
	WitnessShares []WitnessShare
	Threshold     int // k, for reconstruction
	RosterSize    int // n, informational
}

// SiliconWrap is the silicon-bound wrapper. KPALPubKey is the
// X25519 public half of a keypair the host derives from K_PAL
// at boot (via HKDF over K_PAL); the private half is
// re-derived on demand and never persists. The DEK is NaCl-
// boxed to KPALPubKey under an ephemeral sender key so only a
// host that can re-derive K_PAL can reopen it.
type SiliconWrap struct {
	EphemeralPub [32]byte // sender-side one-shot pub
	Nonce        [24]byte // NaCl box nonce
	Ciphertext   []byte   // 48 bytes (32 DEK + 16 poly1305 tag)
}

// WitnessShare is one NaCl-box-encrypted Shamir share.
type WitnessShare struct {
	WitnessIndex int
	EphemeralPub [32]byte
	Nonce        [24]byte
	Ciphertext   []byte
}

// Seal wraps `plaintext` under the silicon fast-path key AND
// Shamir-split + per-witness-boxed shares. The DEK is generated
// inside this function and zeroised before return; callers
// never see it.
//
// `siliconPub` is the X25519 public half the host derives from
// K_PAL (typically via `HKDF(K_PAL, "qee-silicon")` → 32-byte
// seed → `box.GenerateKey(deterministic-seed)`). Here we just
// accept it as bytes for composability.
func Seal(plaintext []byte, siliconPub [32]byte, witnesses []WitnessPubkey, threshold int) (*SealedEnvelope, error) {
	if threshold < 1 || threshold > len(witnesses) {
		return nil, fmt.Errorf("%w: threshold %d outside [1, %d]",
			ErrEnvelope, threshold, len(witnesses))
	}
	// Draw a fresh 32-byte DEK. Used once, zeroised before
	// return. The BOTH wrappers below bind the same DEK.
	var dek [DataKeyBytes]byte
	if _, err := rand.Read(dek[:]); err != nil {
		return nil, fmt.Errorf("%w: dek: %v", ErrEnvelope, err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// ---- Data AEAD -------------------------------------------
	aead, err := chacha20poly1305.New(dek[:])
	if err != nil {
		return nil, fmt.Errorf("%w: aead init: %v", ErrEnvelope, err)
	}
	nonce := make([]byte, DataNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: nonce: %v", ErrEnvelope, err)
	}
	dataCT := aead.Seal(nil, nonce, plaintext, envelopeAD(len(witnesses), threshold))

	// ---- Silicon fast-path wrap -----------------------------
	siliconWrap, err := boxSealDek(dek, siliconPub)
	if err != nil {
		return nil, fmt.Errorf("%w: silicon wrap: %v", ErrEnvelope, err)
	}

	// ---- Shamir split + per-witness box --------------------
	shares, err := Split(dek[:], len(witnesses), threshold)
	if err != nil {
		return nil, fmt.Errorf("%w: shamir split: %v", ErrEnvelope, err)
	}
	wShares := make([]WitnessShare, len(witnesses))
	for i, w := range witnesses {
		// Encode the share as (index byte || share bytes) so the
		// recipient knows which x-coordinate to use on
		// reconstruction.
		body := make([]byte, 1+len(shares[i].Bytes))
		body[0] = shares[i].Index
		copy(body[1:], shares[i].Bytes)

		wrap, err := boxSealGeneric(body, w.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("%w: witness[%d] box: %v", ErrEnvelope, i, err)
		}
		wShares[i] = WitnessShare{
			WitnessIndex: w.Index,
			EphemeralPub: wrap.EphemeralPub,
			Nonce:        wrap.Nonce,
			Ciphertext:   wrap.Ciphertext,
		}
	}
	return &SealedEnvelope{
		DataNonce:     nonce,
		Data:          dataCT,
		SiliconWrap:   siliconWrap,
		WitnessShares: wShares,
		Threshold:     threshold,
		RosterSize:    len(witnesses),
	}, nil
}

// OpenSilicon is the fast path every normal read uses: the
// host that sealed (same K_PAL → same silicon X25519 priv)
// unwraps the DEK directly, bypassing the witness flow.
// Typical cost: one NaCl box open + one AEAD. No network.
func OpenSilicon(env *SealedEnvelope, siliconPub [32]byte, siliconPriv [32]byte) ([]byte, error) {
	if env == nil || env.SiliconWrap == nil {
		return nil, fmt.Errorf("%w: nil silicon wrap", ErrEnvelope)
	}
	dek, err := boxOpenDek(env.SiliconWrap, siliconPub, siliconPriv)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap silicon: %v", ErrEnvelope, err)
	}
	defer zero(dek[:])
	aead, err := chacha20poly1305.New(dek[:])
	if err != nil {
		return nil, fmt.Errorf("%w: aead: %v", ErrEnvelope, err)
	}
	pt, err := aead.Open(nil, env.DataNonce, env.Data,
		envelopeAD(env.RosterSize, env.Threshold))
	if err != nil {
		return nil, fmt.Errorf("%w: aead open: %v", ErrEnvelope, err)
	}
	return pt, nil
}

// RecoverDEK is the FIRST half of the recovery path. Given ≥ k
// decrypted-by-witness shares (each a (index, share_bytes)
// tuple the witness produced after opening its NaCl box),
// reconstruct the DEK. The returned DEK is then used by
// ReSeal (or directly to AEAD-open the data) — but production
// callers should ReSeal immediately so the new host rebinds
// the DEK to its own silicon.
func RecoverDEK(env *SealedEnvelope, decryptedShares []Share) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("%w: nil envelope", ErrEnvelope)
	}
	if len(decryptedShares) < env.Threshold {
		return nil, fmt.Errorf("%w: %d shares, need ≥ %d",
			ErrEnvelope, len(decryptedShares), env.Threshold)
	}
	dek, err := Combine(decryptedShares, env.Threshold)
	if err != nil {
		return nil, fmt.Errorf("%w: shamir combine: %v", ErrEnvelope, err)
	}
	if len(dek) != DataKeyBytes {
		return nil, fmt.Errorf("%w: reconstructed DEK is %d bytes, expected %d",
			ErrEnvelope, len(dek), DataKeyBytes)
	}
	return dek, nil
}

// ReSeal is the SECOND half of the recovery path. It rebinds
// the recovered DEK to a NEW silicon identity (H₂'s
// PUF-derived X25519 pub) and to a NEW roster of witnesses
// (which may be identical to the old roster or rotated). The
// data AEAD stays untouched — this is an O(n) operation on the
// wrappers, not on the ciphertext.
//
// The old envelope's witness wrappers are REPLACED, not merged.
// Callers that need history retention should archive the old
// envelope alongside the new one in the lineage log (ADR-014).
func ReSeal(old *SealedEnvelope, recoveredDEK []byte,
	newSiliconPub [32]byte, newWitnesses []WitnessPubkey, newThreshold int,
) (*SealedEnvelope, error) {
	if len(recoveredDEK) != DataKeyBytes {
		return nil, fmt.Errorf("%w: recovered DEK size %d", ErrEnvelope, len(recoveredDEK))
	}
	if newThreshold < 1 || newThreshold > len(newWitnesses) {
		return nil, fmt.Errorf("%w: new threshold %d out of range",
			ErrEnvelope, newThreshold)
	}
	var dek [DataKeyBytes]byte
	copy(dek[:], recoveredDEK)
	defer zero(dek[:])

	siliconWrap, err := boxSealDek(dek, newSiliconPub)
	if err != nil {
		return nil, err
	}
	shares, err := Split(dek[:], len(newWitnesses), newThreshold)
	if err != nil {
		return nil, err
	}
	wShares := make([]WitnessShare, len(newWitnesses))
	for i, w := range newWitnesses {
		body := make([]byte, 1+len(shares[i].Bytes))
		body[0] = shares[i].Index
		copy(body[1:], shares[i].Bytes)
		wrap, err := boxSealGeneric(body, w.Pubkey)
		if err != nil {
			return nil, err
		}
		wShares[i] = WitnessShare{
			WitnessIndex: w.Index,
			EphemeralPub: wrap.EphemeralPub,
			Nonce:        wrap.Nonce,
			Ciphertext:   wrap.Ciphertext,
		}
	}
	return &SealedEnvelope{
		DataNonce:     old.DataNonce,
		Data:          old.Data,
		SiliconWrap:   siliconWrap,
		WitnessShares: wShares,
		Threshold:     newThreshold,
		RosterSize:    len(newWitnesses),
	}, nil
}

// WitnessUnboxShare is the witness-side helper each witness
// runs during a recovery. Given its own long-term X25519
// keypair and its assigned WitnessShare, it returns the
// plaintext Shamir share. The witness NEVER sees the DEK —
// the combining happens at the new host with its k collected
// shares.
func WitnessUnboxShare(ws WitnessShare, witnessPub, witnessPriv [32]byte) (Share, error) {
	inner, err := boxOpenGeneric(ws.EphemeralPub, ws.Nonce, ws.Ciphertext, witnessPub, witnessPriv)
	if err != nil {
		return Share{}, fmt.Errorf("%w: witness unbox: %v", ErrEnvelope, err)
	}
	if len(inner) < 2 {
		return Share{}, fmt.Errorf("%w: inner share too short", ErrEnvelope)
	}
	return Share{Index: inner[0], Bytes: append([]byte(nil), inner[1:]...)}, nil
}

// -----------------------------------------------------------------
// NaCl box helpers — factored out so the three call sites
// (SiliconWrap, per-witness, and witness-side open) share one
// implementation.

func boxSealDek(dek [DataKeyBytes]byte, recipientPub [32]byte) (*SiliconWrap, error) {
	inner, err := boxSealGeneric(dek[:], recipientPub)
	if err != nil {
		return nil, err
	}
	return &SiliconWrap{
		EphemeralPub: inner.EphemeralPub,
		Nonce:        inner.Nonce,
		Ciphertext:   inner.Ciphertext,
	}, nil
}

func boxOpenDek(w *SiliconWrap, recipientPub, recipientPriv [32]byte) ([]byte, error) {
	return boxOpenGeneric(w.EphemeralPub, w.Nonce, w.Ciphertext, recipientPub, recipientPriv)
}

type boxResult struct {
	EphemeralPub [32]byte
	Nonce        [24]byte
	Ciphertext   []byte
}

func boxSealGeneric(payload []byte, recipientPub [32]byte) (*boxResult, error) {
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ct := box.Seal(nil, payload, &nonce, &recipientPub, ephPriv)
	return &boxResult{
		EphemeralPub: *ephPub,
		Nonce:        nonce,
		Ciphertext:   ct,
	}, nil
}

func boxOpenGeneric(ephPub [32]byte, nonce [24]byte, ct []byte, recipientPub, recipientPriv [32]byte) ([]byte, error) {
	_ = recipientPub // NaCl box.Open does not use the recipient pub; kept for API symmetry and clarity
	out, ok := box.Open(nil, ct, &nonce, &ephPub, &recipientPriv)
	if !ok {
		return nil, errors.New("qee: nacl box.Open failed")
	}
	return out, nil
}

// envelopeAD produces the authenticated-data bytes the AEAD
// binds. Making RosterSize and Threshold part of AD means an
// attacker who substitutes a low-threshold envelope cannot
// reuse the AEAD body.
func envelopeAD(rosterSize, threshold int) []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(rosterSize))
	binary.BigEndian.PutUint64(buf[8:16], uint64(threshold))
	return buf[:]
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
