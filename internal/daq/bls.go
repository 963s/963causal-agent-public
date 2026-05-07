// Package daq — Distributed Attestation Quorum.
//
// bls.go is the cryptographic primitive layer. It wraps
// github.com/drand/kyber with a small, opinionated API tailored to
// what the rest of the DAQ code needs:
//
//   • A single "scheme" (BLS12-381, BDN signatures in G1, pubkeys in
//     G2) frozen at package-init. Callers do not pick curves.
//
//   • Bytes-in / bytes-out signing helpers. The rest of the codebase
//     never holds a kyber.Scalar or kyber.Point, only Go byte slices.
//
//   • An aggregate-with-bitmask API (AggregateSigs, VerifyAggregate)
//     because that is what the DAQ ticket actually carries. The
//     bitmask is an explicit participation list so the server can
//     tell "which 3 of the 5 witnesses consented", not just "at least
//     3 did".
//
// Why BDN (Boneh-Drijvers-Neven) and not a plain BLS aggregate: BDN
// adds a per-signer coefficient `H(pk_i, {pk_1..pk_n})` to each
// signature and public-key term before aggregation. This defeats
// rogue-key attacks without requiring a proof-of-possession step at
// enrolment — an attacker who registers `pk_evil = pk_target - pk_other`
// cannot produce a valid aggregate because the coefficients mix every
// pubkey in the roster. See https://eprint.iacr.org/2018/483.pdf.
//
// Why not true-threshold BLS (tBLS): we want the *identity* of the
// signing witnesses to be auditable (bitmask in the ticket); a tBLS
// aggregate collapses all signers into a single group-key-derived
// signature, which would force us to either store proofs of
// participation out-of-band or trust a dealer. Aggregate-BLS is the
// right primitive for "3 of 5 auditable witnesses". This is the same
// choice Ethereum made for its attestation aggregation path.
package daq

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	blsbn "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
)

// PubkeySize is the serialised length of a BDN public key (G2 point
// compressed). Exported as a constant so parsers can pre-size slices
// and validators can reject malformed keys cheaply.
const PubkeySize = 96

// SignatureSize is the serialised length of a BDN signature (G1 point
// compressed).
const SignatureSize = 48

// suite is the single BLS12-381 pairing suite used by every DAQ
// component. Declared once at package scope to make sure the witness
// service, the agent's DAQ client, and the verifier all agree on the
// same pairing instance (and therefore the same DST for hash-to-curve).
var suite pairing.Suite = blsbn.NewBLS12381Suite()

// scheme is the BDN signature scheme on top of `suite`, signing into
// G1 (48-byte sigs) with public keys in G2 (96-byte keys).
var scheme = bdn.NewSchemeOnG1(suite)

// randomStream returns a Kyber cipher.Stream drawn from crypto/rand.
// Kept as a helper so tests can inject a deterministic stream without
// reaching into the scheme type.
func randomStream() cipher.Stream {
	return suite.RandomStream()
}

// PrivateKey holds a BDN signing scalar. It is never serialised
// directly outside this package; use Marshal / Unmarshal on the
// PublicKey instead. The zero value is invalid.
type PrivateKey struct {
	s kyber.Scalar
	p kyber.Point // cached pub; derived once at construction
}

// PublicKey holds a BDN verification point. Callers shuttle these
// between processes as raw bytes via Marshal / UnmarshalPublicKey.
type PublicKey struct {
	p kyber.Point
}

// GenerateKeyPair draws a fresh BDN keypair from crypto/rand. The
// private scalar is kept in memory only; callers that need to persist
// it (witness daemons) should call PrivateKey.MarshalBinary and treat
// the result like any other 32-byte secret.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	s, p := scheme.NewKeyPair(randomStream())
	return &PrivateKey{s: s, p: p}, &PublicKey{p: p}, nil
}

// GenerateKeyPairFromStream lets callers supply their own entropy.
// Unused in production; smoke-tests use it with a deterministic stream
// so golden test vectors stay stable across CI runs.
func GenerateKeyPairFromStream(r cipher.Stream) (*PrivateKey, *PublicKey) {
	if r == nil {
		r = randomStream()
	}
	s, p := scheme.NewKeyPair(r)
	return &PrivateKey{s: s, p: p}, &PublicKey{p: p}
}

// Public returns the matching PublicKey without exposing internals.
func (k *PrivateKey) Public() *PublicKey {
	if k == nil || k.p == nil {
		return nil
	}
	return &PublicKey{p: k.p.Clone()}
}

// MarshalBinary serialises the private scalar. Witness daemons use
// this to persist their key to disk; production code should treat the
// output as secret material (chmod 0600 etc.).
func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.s == nil {
		return nil, errors.New("daq: marshal on nil private key")
	}
	return k.s.MarshalBinary()
}

// UnmarshalPrivateKey restores a PrivateKey persisted via
// MarshalBinary. Also recomputes and caches the matching public key.
func UnmarshalPrivateKey(b []byte) (*PrivateKey, error) {
	s := suite.G2().Scalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("daq: unmarshal private key: %w", err)
	}
	p := suite.G2().Point().Mul(s, nil) // public = s * G2_base
	return &PrivateKey{s: s, p: p}, nil
}

// MarshalBinary serialises the public point to 96 bytes.
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	if p == nil || p.p == nil {
		return nil, errors.New("daq: marshal on nil public key")
	}
	return p.p.MarshalBinary()
}

// UnmarshalPublicKey parses a 96-byte BDN public key.
func UnmarshalPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PubkeySize {
		return nil, fmt.Errorf("daq: public key must be %d bytes, got %d", PubkeySize, len(b))
	}
	p := suite.G2().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("daq: unmarshal public key: %w", err)
	}
	return &PublicKey{p: p}, nil
}

// Equal reports whether two public keys represent the same group
// element. Used by the aggregator to detect accidental double-inclusion
// of the same witness in a quorum.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	return p.p.Equal(other.p)
}

// Sign produces a BDN signature on `msg` with the given private key.
// The message is hashed internally by the scheme (hash-to-curve on
// G1 with the pairing suite's default DST); callers must pre-hash if
// they want a shorter signing input. DAQ's protocol.go already does
// that via canonicalMessage().
func Sign(priv *PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("daq: sign with nil key")
	}
	return scheme.Sign(priv.s, msg)
}

// VerifyIndividual checks a single (pub, sig) pair against `msg`.
// This is the path a witness uses to pre-check signatures in a
// sequential-chain hand-off before signing its own message.
func VerifyIndividual(pub *PublicKey, msg, sig []byte) error {
	if pub == nil {
		return errors.New("daq: verify with nil key")
	}
	return scheme.Verify(pub.p, msg, sig)
}

// AggregateResult bundles everything the verifier needs to validate
// a quorum: the aggregated signature (48 B) and the bitmask selecting
// which roster positions contributed. The roster itself is *not*
// carried here — it is shared between agent and server at enrolment
// time, so the bitmask is meaningful to both sides.
type AggregateResult struct {
	// Signature is the BDN-aggregated point in G1, serialised.
	Signature []byte
	// Mask is the participation bitmask. Bit i corresponds to roster
	// position i; a set bit means "this witness contributed". The
	// wire layout follows kyber's sign.Mask: little-endian within
	// each byte, byte 0 covers positions 0..7.
	Mask []byte
	// Count is the number of participating witnesses, for convenience.
	Count int
}

// AggregateSigs combines the given individual signatures into a BDN
// aggregate according to the participation mask implied by
// `participantIndexes`. `roster` is the ordered list of every
// witness's public key; `participantIndexes` names which positions
// contributed, and `sigs` must be in the *same order* as those
// positions (the helper does not reorder by index — callers that
// collect asynchronously should sort before calling).
func AggregateSigs(roster []*PublicKey, participantIndexes []int, sigs [][]byte) (*AggregateResult, error) {
	if len(roster) == 0 {
		return nil, errors.New("daq: empty roster")
	}
	if len(participantIndexes) != len(sigs) {
		return nil, fmt.Errorf("daq: participant count %d != sig count %d",
			len(participantIndexes), len(sigs))
	}
	pubs := make([]kyber.Point, len(roster))
	for i, pk := range roster {
		if pk == nil || pk.p == nil {
			return nil, fmt.Errorf("daq: nil pubkey at roster[%d]", i)
		}
		pubs[i] = pk.p
	}
	mask, err := sign.NewMask(suite, pubs, nil)
	if err != nil {
		return nil, fmt.Errorf("daq: new mask: %w", err)
	}
	for _, idx := range participantIndexes {
		if idx < 0 || idx >= len(roster) {
			return nil, fmt.Errorf("daq: participant index %d out of roster size %d",
				idx, len(roster))
		}
		if err := mask.SetBit(idx, true); err != nil {
			return nil, fmt.Errorf("daq: mask set bit %d: %w", idx, err)
		}
	}
	aggPoint, err := scheme.AggregateSignatures(sigs, mask)
	if err != nil {
		return nil, fmt.Errorf("daq: aggregate signatures: %w", err)
	}
	aggBytes, err := aggPoint.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("daq: marshal aggregate: %w", err)
	}
	return &AggregateResult{
		Signature: aggBytes,
		Mask:      mask.Mask(),
		Count:     mask.CountEnabled(),
	}, nil
}

// VerifyAggregate checks a DAQ aggregate against the original
// message. It reconstructs the participation mask from the supplied
// bitmask, aggregates the public keys of the named participants using
// BDN's coefficient-weighted scheme, and then verifies the aggregate
// signature against that aggregate key. A successful verification
// implies that every masked witness signed `msg` — under the security
// assumption that at most k-1 witnesses are dishonest.
func VerifyAggregate(roster []*PublicKey, maskBytes, sig, msg []byte, minParticipants int) error {
	if len(roster) == 0 {
		return errors.New("daq: empty roster")
	}
	if len(sig) != SignatureSize {
		return fmt.Errorf("daq: signature must be %d bytes, got %d", SignatureSize, len(sig))
	}
	pubs := make([]kyber.Point, len(roster))
	for i, pk := range roster {
		if pk == nil || pk.p == nil {
			return fmt.Errorf("daq: nil pubkey at roster[%d]", i)
		}
		pubs[i] = pk.p
	}
	mask, err := sign.NewMask(suite, pubs, nil)
	if err != nil {
		return fmt.Errorf("daq: new mask: %w", err)
	}
	if err := mask.SetMask(maskBytes); err != nil {
		return fmt.Errorf("daq: set mask: %w", err)
	}
	if got := mask.CountEnabled(); got < minParticipants {
		return fmt.Errorf("daq: only %d witnesses in aggregate, need ≥ %d",
			got, minParticipants)
	}
	aggPub, err := scheme.AggregatePublicKeys(mask)
	if err != nil {
		return fmt.Errorf("daq: aggregate pubkeys: %w", err)
	}
	return scheme.Verify(aggPub, msg, sig)
}

// Participants walks a mask and returns the roster indices of the
// bits that are set. Used by the client for logging and by the server
// for building audit rows listing which witnesses actually signed.
func Participants(roster []*PublicKey, maskBytes []byte) ([]int, error) {
	if len(roster) == 0 {
		return nil, errors.New("daq: empty roster")
	}
	pubs := make([]kyber.Point, len(roster))
	for i, pk := range roster {
		pubs[i] = pk.p
	}
	mask, err := sign.NewMask(suite, pubs, nil)
	if err != nil {
		return nil, err
	}
	if err := mask.SetMask(maskBytes); err != nil {
		return nil, err
	}
	out := make([]int, 0, mask.CountEnabled())
	for i := 0; i < mask.CountTotal(); i++ {
		if bit := mask.Mask()[i/8] & (1 << uint(i%8)); bit != 0 {
			out = append(out, i)
		}
	}
	return out, nil
}

// Static guard so the linter reminds us to keep using crypto/rand
// (never math/rand) anywhere a key is born.
var _ = rand.Reader
