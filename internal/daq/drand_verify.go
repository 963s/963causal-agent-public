package daq

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	blsbn "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

// drandSchemeUnchainedG1Rfc9380 is the scheme ID League of Entropy's
// fastnet uses (discoverable at /info; `schemeID` field). We hardcode
// it because the verifier has to pick a message-construction shape,
// and any other shape is a silent verify-always-fails trap.
const drandSchemeUnchainedG1Rfc9380 = "bls-unchained-g1-rfc9380"

// drandSchemeUnchainedG1 is the legacy name from the early fastnet
// rollout; kept for completeness so an operator pointing at a chain
// that still reports the old ID is told explicitly instead of getting
// a mysterious "sig invalid" failure.
const drandSchemeUnchainedG1 = "bls-unchained-g1"

// drandMsgBLSUnchained returns the bytes the drand beacon signed for
// `round` on an unchained chain: the 32-byte SHA-256 of the round
// number encoded as a big-endian uint64.
//
// Drand uses this construction verbatim on fastnet; the 32-byte
// output is then hashed to a G1 point with the RFC 9380 DST baked
// into kyber's default G1 group (see kyber_g1.go:domainG1).
func drandMsgBLSUnchained(round uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], round)
	sum := sha256.Sum256(buf[:])
	return sum[:]
}

// VerifyDrandBeacon checks a fastnet beacon `(round, sig)` against the
// supplied chain public key. Uses kyber's BLS scheme on G1 with the
// default RFC-9380 DST — the exact construction drand-client uses
// internally. Returns nil on success; the error carries enough
// context for operators to tell "bad sig" apart from "wrong curve
// point" or "empty pubkey".
//
// The chain public key is the 96-byte G2 point served at
// /<chain>/info.public_key. It is a static per-chain value and
// should be pinned by the operator (we pin it in
// DrandClient.WellKnownChainPubkey below).
func VerifyDrandBeacon(round uint64, sig, chainPub []byte) error {
	if len(sig) != 48 {
		return fmt.Errorf("daq/drand: sig must be 48B, got %d", len(sig))
	}
	if len(chainPub) != 96 {
		return fmt.Errorf("daq/drand: chain pubkey must be 96B, got %d", len(chainPub))
	}
	if round == 0 {
		return errors.New("daq/drand: round 0 is the invalid sentinel")
	}

	// Bring up a fresh suite so the DST is the library default (which
	// already matches drand's RFC-9380 DST — see
	// kyber-bls12381/kyber_g1.go:domainG1).
	suite := blsbn.NewBLS12381Suite()
	scheme := bls.NewSchemeOnG1(suite)

	pubPoint := suite.G2().Point()
	if err := pubPoint.UnmarshalBinary(chainPub); err != nil {
		return fmt.Errorf("daq/drand: unmarshal chain pubkey: %w", err)
	}
	msg := drandMsgBLSUnchained(round)
	if err := scheme.Verify(pubPoint, msg, sig); err != nil {
		return fmt.Errorf("daq/drand: beacon signature invalid: %w", err)
	}
	return nil
}

// WellKnownFastnetChainPubkey is the League of Entropy fastnet
// (quicknet) chain public key, pinned so we do not have to trust
// whatever the relay serves at /info.public_key. Operators that want
// to track a different drand chain should pass their pinned key to
// DrandClient.WithPinnedPubkey.
//
// Source: https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
// schemeID = bls-unchained-g1-rfc9380
// 96-byte hex, G2 compressed.
const WellKnownFastnetChainPubkey = "" +
	"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c" +
	"8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb" +
	"5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"

// ExpectedChainPubkey returns the bytes of WellKnownFastnetChainPubkey
// decoded. Panics at init time if the constant is malformed, since
// that is a compile-time invariant rather than a runtime condition.
func ExpectedChainPubkey() []byte {
	b, err := hex.DecodeString(WellKnownFastnetChainPubkey)
	if err != nil || len(b) != 96 {
		panic(fmt.Sprintf("daq/drand: well-known pubkey malformed: %v", err))
	}
	return b
}

// ValidateChainScheme refuses chains whose scheme ID would break our
// message-construction assumption. Called from the witness startup
// after fetching /info, so operators see the incompatibility clearly
// at boot rather than at the first verify failure.
func ValidateChainScheme(schemeID string) error {
	switch schemeID {
	case drandSchemeUnchainedG1Rfc9380, drandSchemeUnchainedG1, "":
		// Empty = older chain that served no schemeID; fastnet
		// response pre-2024 sometimes omitted it.
		return nil
	default:
		return fmt.Errorf("daq/drand: unsupported chain scheme %q (expected %q)",
			schemeID, drandSchemeUnchainedG1Rfc9380)
	}
}
