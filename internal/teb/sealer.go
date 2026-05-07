package teb

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// KeySize and NonceSize are the standard ChaCha20-Poly1305
// parameters. Exported for unit tests that need to craft
// malformed inputs.
const (
	KeySize   = chacha20poly1305.KeySize   // 32
	NonceSize = chacha20poly1305.NonceSize // 12
)

// SealedBlob is the public artefact a TEB seal emits. It carries
// the ciphertext plus every parameter an honest opener needs to
// reproduce the decryption key by sampling the environment
// afresh — zone id, the exact sealed window, the quantisation
// cadence, and a random salt so two seals of the same plaintext
// under the same (zone, window) still produce distinct
// ciphertexts. The blob is PURE public data: losing it to an
// adversary leaks nothing about the plaintext.
type SealedBlob struct {
	// ZoneID the sealer was bound to. Opener MUST be in the
	// same zone or the HKDF input diverges.
	ZoneID ZoneID
	// WindowStartMs and WindowDurationMs delimit the epoch of
	// validity. Opener MUST call Open() while t ∈
	// [WindowStartMs, WindowStartMs+WindowDurationMs] — outside
	// this range, re-sampling the environment yields a
	// statistically-independent signal (property P2 of
	// DeterministicSignal).
	WindowStartMs    int64
	WindowDurationMs int64
	// CadenceMs is the sampling step the sealer used. The opener
	// MUST match it exactly; even sub-ms mismatch walks into a
	// different HKDF input. In production the cadence is fixed
	// at protocol level; here we carry it for clarity.
	CadenceMs int64
	// Salt is 16 bytes of randomness that prevent two
	// SealedBlobs under the same (zone, window) from colliding.
	Salt []byte
	// Ciphertext is the ChaCha20-Poly1305 sealed plaintext; the
	// nonce is prefixed (first 12 bytes).
	Ciphertext []byte
}

// DeriveKey is the TEB key-derivation primitive. It takes the
// agent-held `bindingSecret` (typically a PUF-derived secret
// from W5b — for the PoC it can be any high-entropy byte string)
// plus the environmental samples, runs them through HKDF, and
// emits a 32-byte symmetric key. The same inputs always yield
// the same output; diverging inputs yield cryptographically-
// independent outputs.
func DeriveKey(bindingSecret []byte, zone ZoneID, samples []Sample, salt []byte) ([]byte, error) {
	if len(bindingSecret) == 0 {
		return nil, errors.New("teb: empty binding secret")
	}
	if len(samples) == 0 {
		return nil, errors.New("teb: empty sample vector")
	}
	if len(salt) == 0 {
		return nil, errors.New("teb: empty salt")
	}
	// HKDF info string: deterministic serialisation of the
	// zone + quantised samples. Any change to any sample flips
	// a bucket and changes the info string → changes the key.
	var info []byte
	info = append(info, []byte("963causal-TEB-V1|")...)
	var zb [4]byte
	binary.BigEndian.PutUint16(zb[:2], uint16(zone))
	info = append(info, zb[:2]...)
	info = append(info, '|')
	info = append(info, QuantiseSamples(samples)...)

	h := hkdf.New(sha3.New256, bindingSecret, salt, info)
	key := make([]byte, KeySize)
	if _, err := h.Read(key); err != nil {
		return nil, fmt.Errorf("teb: hkdf: %w", err)
	}
	return key, nil
}

// Seal encrypts `plaintext` under a TEB-derived key and returns
// the SealedBlob. Caller specifies the environmental window
// during which opens are permitted; outside it the blob is
// cryptographically dead (provided P2 / autocorrelation holds).
//
// The binding-secret argument is the long-lived secret the host
// can always recompute (e.g. W5b K_PAL). It is HMAC'd together
// with the environmental samples so an attacker who steals the
// blob AND the binding secret still cannot open after the
// window, because the environmental component is unreachable.
func Seal(
	src EnvSource,
	bindingSecret []byte,
	zone ZoneID,
	windowStartMs, windowDurationMs, cadenceMs int64,
	plaintext []byte,
) (*SealedBlob, error) {
	if src == nil {
		return nil, errors.New("teb: seal with nil env source")
	}
	samples, err := SampleWindow(src, zone, windowStartMs, windowDurationMs, cadenceMs)
	if err != nil {
		return nil, fmt.Errorf("teb: sample window: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("teb: salt: %w", err)
	}
	key, err := DeriveKey(bindingSecret, zone, samples, salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("teb: aead init: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("teb: nonce: %w", err)
	}
	// Authenticated-data layout binds the blob's public
	// parameters into the AEAD tag; an attacker who edits
	// ZoneID or WindowStartMs post-hoc flips the tag check.
	ad := aeadHeader(zone, windowStartMs, windowDurationMs, cadenceMs, salt)
	sealed := aead.Seal(nonce, nonce, plaintext, ad)

	// Zeroise the derived key before it leaves scope. We cannot
	// enforce that Go's GC recycles the backing array; a
	// production port would mlock + explicit_bzero here.
	for i := range key {
		key[i] = 0
	}

	return &SealedBlob{
		ZoneID:           zone,
		WindowStartMs:    windowStartMs,
		WindowDurationMs: windowDurationMs,
		CadenceMs:        cadenceMs,
		Salt:             salt,
		Ciphertext:       sealed,
	}, nil
}

// Open is the verifier-facing side of the primitive. It
// re-samples the environment at (zone, window), re-derives the
// key, and tries to AEAD-open the ciphertext. Three failure
// modes operators should distinguish:
//
//   * ErrOutOfWindow  — wall clock is outside the sealed window
//   * ErrWrongZone    — opener's zone differs from the sealed one
//   * ErrOpen         — AEAD tag didn't verify (catch-all: can
//                       mean wrong binding secret, tampered blob,
//                       or an environmental mismatch the zone/
//                       window checks failed to catch).
//
// `nowMs` is the opener's notion of "now"; we take it as input
// instead of calling time.Now() so unit tests can drive
// deterministic scenarios.
func Open(
	src EnvSource,
	bindingSecret []byte,
	blob *SealedBlob,
	openerZone ZoneID,
	nowMs int64,
) ([]byte, error) {
	if blob == nil {
		return nil, errors.New("teb: nil blob")
	}
	if openerZone != blob.ZoneID {
		return nil, ErrWrongZone
	}
	if nowMs < blob.WindowStartMs || nowMs > blob.WindowStartMs+blob.WindowDurationMs {
		return nil, ErrOutOfWindow
	}
	samples, err := SampleWindow(src, blob.ZoneID,
		blob.WindowStartMs, blob.WindowDurationMs, blob.CadenceMs)
	if err != nil {
		return nil, fmt.Errorf("teb: resample: %w", err)
	}
	key, err := DeriveKey(bindingSecret, blob.ZoneID, samples, blob.Salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("teb: aead: %w", err)
	}
	if len(blob.Ciphertext) < NonceSize+chacha20poly1305.Overhead {
		return nil, ErrOpen
	}
	nonce := blob.Ciphertext[:NonceSize]
	body := blob.Ciphertext[NonceSize:]
	ad := aeadHeader(blob.ZoneID, blob.WindowStartMs, blob.WindowDurationMs,
		blob.CadenceMs, blob.Salt)
	plaintext, err := aead.Open(nil, nonce, body, ad)
	// Zeroise before return, happy path or sad.
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// ErrOutOfWindow, ErrWrongZone, ErrOpen are the sentinel errors
// Open returns so callers can distinguish the three families of
// failure without parsing messages.
var (
	ErrOutOfWindow = errors.New("teb: outside sealed window")
	ErrWrongZone   = errors.New("teb: opener zone differs from sealer zone")
	ErrOpen        = errors.New("teb: AEAD open failed")
)

// CurrentMs is a small convenience for callers that want the
// ambient wall clock without importing time themselves.
func CurrentMs() int64 {
	return time.Now().UnixMilli()
}

// aeadHeader is the public authenticated-data we bind into
// every ChaCha20-Poly1305 seal. Changing any byte here between
// seal and open changes the AEAD tag and forces a failure.
func aeadHeader(zone ZoneID, startMs, durationMs, cadenceMs int64, salt []byte) []byte {
	out := make([]byte, 0, 2+8*3+len(salt))
	var zb [2]byte
	binary.BigEndian.PutUint16(zb[:], uint16(zone))
	out = append(out, zb[:]...)
	for _, v := range []int64{startMs, durationMs, cadenceMs} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		out = append(out, b[:]...)
	}
	out = append(out, salt...)
	return out
}

// DebugString is a tiny helper for the demo binary to print a
// SealedBlob without dumping 10 kB of ciphertext.
func (b *SealedBlob) DebugString() string {
	if b == nil {
		return "<nil blob>"
	}
	return fmt.Sprintf("SealedBlob{zone=%d window=[%d,+%d]ms cadence=%dms salt=%s… ct=%d B}",
		b.ZoneID, b.WindowStartMs, b.WindowDurationMs, b.CadenceMs,
		hex.EncodeToString(b.Salt)[:8], len(b.Ciphertext))
}

// Compile-time guard that chacha20poly1305.New really returns
// a cipher.AEAD. Pure documentation; zero runtime cost.
var _ = func() cipher.AEAD {
	a, _ := chacha20poly1305.New(make([]byte, KeySize))
	return a
}
