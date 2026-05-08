// Package identity owns the agent's durable Ed25519 identity key and its
// ephemeral X25519 keypair used for session-key agreement with the control
// plane.
//
// The Ed25519 key lives on disk at 0600 and is generated once at first run.
// The X25519 keypair is ephemeral per handshake and never touches disk.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
)

// MlockSecret attempts to lock a byte slice into physical RAM so it
// cannot be swapped to disk. Logs a warning on failure instead of
// crashing — mlock is defence-in-depth, not a hard gate.
// On non-Linux platforms this is a no-op.
func MlockSecret(b []byte) {
	if runtime.GOOS != "linux" || len(b) == 0 {
		return
	}
	if err := unix.Mlock(b); err != nil {
		log.Printf("warn: mlock(%d bytes) failed: %v (secret may be swappable)", len(b), err)
	}
}

type HostKey struct {
	EdPublic  ed25519.PublicKey
	EdPrivate ed25519.PrivateKey
}

// Zero wipes the private key material from memory. Call at process
// shutdown for defence-in-depth; the key cannot be recovered without
// reloading from disk.
func (hk *HostKey) Zero() {
	for i := range hk.EdPrivate {
		hk.EdPrivate[i] = 0
	}
}

type persisted struct {
	Version int    `json:"version"`
	EdPriv  string `json:"ed25519_private_b64"`
	EdPub   string `json:"ed25519_public_b64"`
}

func LoadOrCreate(path string) (*HostKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir keystore: %w", err)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return generate(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse keystore: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(p.EdPriv)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length")
	}
	pub, err := base64.StdEncoding.DecodeString(p.EdPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length")
	}
	hk := &HostKey{EdPublic: pub, EdPrivate: priv}
	MlockSecret(hk.EdPrivate)
	return hk, nil
}

func generate(path string) (*HostKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	p := persisted{
		Version: 1,
		EdPriv:  base64.StdEncoding.EncodeToString(priv),
		EdPub:   base64.StdEncoding.EncodeToString(pub),
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := writeAtomic(path, b, 0o600); err != nil {
		return nil, err
	}
	hk := &HostKey{EdPublic: pub, EdPrivate: priv}
	MlockSecret(hk.EdPrivate)
	return hk, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".963causal-key-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// X25519 ephemeral keypair (never persisted).

type ECDHKey struct {
	Private [32]byte
	Public  [32]byte
}

func NewECDH() (*ECDHKey, error) {
	k := &ECDHKey{}
	if _, err := io.ReadFull(rand.Reader, k.Private[:]); err != nil {
		return nil, err
	}
	// Clamp as per RFC 7748.
	k.Private[0] &= 248
	k.Private[31] &= 127
	k.Private[31] |= 64
	pub, err := curve25519.X25519(k.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(k.Public[:], pub)
	return k, nil
}

// SharedSecret derives the X25519 shared secret with the server's public key.
func (k *ECDHKey) SharedSecret(serverPub []byte) ([]byte, error) {
	if len(serverPub) != 32 {
		return nil, fmt.Errorf("invalid server X25519 public: %d bytes", len(serverPub))
	}
	return curve25519.X25519(k.Private[:], serverPub)
}

// Zero wipes the private key from memory.
func (k *ECDHKey) Zero() {
	for i := range k.Private {
		k.Private[i] = 0
	}
}
