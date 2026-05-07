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
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

type HostKey struct {
	EdPublic  ed25519.PublicKey
	EdPrivate ed25519.PrivateKey
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
	return &HostKey{EdPublic: pub, EdPrivate: priv}, nil
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
	return &HostKey{EdPublic: pub, EdPrivate: priv}, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
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
