// Package payload derives the session key from the handshake and decrypts the
// probe configuration in memory.
//
// Session key derivation:
//   shared = X25519(agent_x_priv, server_x_pub)
//   session_key = HKDF-SHA3-256(shared, salt="963causal/session/v1", info=host_id || license_key)
//
// Payload is ChaCha20-Poly1305(session_key, nonce) of a serialized ProbeConfig.
package payload

import (
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	SessionKeySalt = "963causal/session/v1"
	SessionKeyLen  = 32
)

// DeriveSessionKey turns the X25519 shared secret into a 32-byte ChaCha20 key.
func DeriveSessionKey(shared []byte, hostID, licenseKey string) ([]byte, error) {
	info := append([]byte(hostID), 0x1f)
	info = append(info, []byte(licenseKey)...)
	r := hkdf.New(sha3.New256, shared, []byte(SessionKeySalt), info)
	key := make([]byte, SessionKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// Decrypt opens a ChaCha20-Poly1305 ciphertext with the derived session key.
// The plaintext is the protobuf-encoded ProbeConfig.
func Decrypt(sessionKey, nonce, ciphertext []byte) ([]byte, error) {
	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("bad session key length: %d", len(sessionKey))
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("bad nonce length: %d", len(nonce))
	}
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aead open: %w (payload rejected)", err)
	}
	return pt, nil
}

// SessionKeyHash returns the sha3-256 hex of a session key (used for
// server-side enrollment tracking, never for anything security-critical).
func SessionKeyHash(key []byte) string {
	s := sha3.Sum256(key)
	return hex.EncodeToString(s[:])
}

// Zero wipes a key buffer.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
