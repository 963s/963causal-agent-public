// Package lbs — Local Blindness Signing.
//
// Problem statement (W11, response to the "Post-Quantum Local
// Blindness" memo). The agent post-W7 holds a PUF-derived Ed25519
// identity whose private half briefly materialises in RAM every
// time Reproduce is called. A Ring -1 attacker on the
// same VM can, in principle, exfiltrate that key during the
// millisecond window (ADR-008 acknowledged this openly for SGRS).
//
// LBS removes the signing capability from the agent entirely:
//
//   1. At enrollment, the agent derives a fresh BLS12-381 secret
//      scalar `s` — call it the *identity secret* — and
//      generates the public identity `P = s·G₂`.
//   2. The agent splits `s` into n Shamir shares
//      (s_1, …, s_n) with threshold k, distributes each share
//      to one witness over the authenticated DAQ channel, and
//      immediately zeroises the polynomial coefficients and the
//      secret itself.
//   3. Post-enrolment the agent holds ONLY the public artefacts:
//      P, the polynomial commitments C_0..C_{k-1}, and whatever
//      authentication material the DAQ layer needs.
//   4. Signing becomes a distributed operation: agent asks k
//      witnesses for partial signatures on message M; each
//      witness computes σ_i = s_i · H(M) in G₁; k partial sigs
//      combine into the full BLS signature σ = s · H(M) via
//      Lagrange interpolation.
//   5. Verification is the standard BLS pairing check
//      e(σ, G₂) == e(H(M), P). No knowledge of `s` is needed
//      beyond what's in P.
//
// Post-enrolment **threat claim** (provable, not marketing):
//
//   Under the DDH / co-CDH assumption on BLS12-381 and the Random
//   Oracle model for the hash-to-curve, an adversary that
//   compromises the agent's entire persistent state after
//   enrolment cannot produce any valid signature under P unless
//   it also recovers k-1 Shamir shares from disjoint witnesses.
//
// Proof sketch:
//
//   The agent's post-enrolment state carries only {P, C_0..C_{k-1}}
//   and DAQ auth material. P leaks no info about s beyond
//   P = s·G₂ (discrete log on G₂ is hard). The polynomial
//   commitments expose degree-k-1 evaluations but reveal no
//   shares below the threshold (information-theoretic security of
//   Shamir). Therefore any signing oracle reduces to either
//   (a) solving co-CDH (extracting s from P), or (b) compromising
//   k witnesses, contradicting the single-host compromise model.
//   ∎
//
// Limitations (stated up-front — this IS the PoC, not a shipped
// product):
//
//   * The PoC uses **trusted-dealer** Shamir. For ≈1 ms at t=0
//     the full `s` exists in the agent's RAM. Pedersen DKG
//     removes this window at the cost of a 2-round interactive
//     protocol between agent and witnesses; see `ADR-009 §5`
//     "Production upgrade path".
//   * The PoC uses BLS12-381 for continuity with W6/W7's witness
//     stack. An Ed25519-native LBS would require FROST-Ed25519
//     (Komlo-Goldberg 2020), which has no mature Go implementation
//     today. BLS is strictly stronger for threshold signing — the
//     BLS aggregate is algebraically clean whereas FROST has
//     subtleties around round commitments.
//   * "Authentication" to witnesses is out of scope of this
//     package — witnesses trust whoever speaks the DAQ bearer
//     token (W7 bearer-token auth). A full deployment would
//     bind every signing request to a DAQ ticket so the agent
//     still cannot trigger signatures without a k-of-n quorum
//     independently agreeing the request is legitimate.
package lbs

import (
	"errors"
	"fmt"

	blsbn "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
)

// suite is the single pairing context used by the whole LBS flow.
// Frozen at init so every enrolment, partial sig, and recovery
// stays on the same curve / DST.
var suite pairing.Suite = blsbn.NewBLS12381Suite()

// scheme is the threshold-BLS-on-G1 signing primitive. G1 for
// signatures (48 B), G2 for public keys (96 B) — consistent with
// internal/daq/bls.go's BDN choice so all BLS objects in the
// codebase share a format convention.
var scheme = tbls.NewThresholdSchemeOnG1(suite)

// blsScheme is the plain (non-threshold) BLS signer we use only
// for the final-verify step. The tbls Recover returns a raw
// signature that verifies identically under plain BLS.
var blsScheme = bls.NewSchemeOnG1(suite)

// PublicIdentity is the non-secret artefact an LBS-enrolled agent
// keeps on local disk (and publishes to the control plane).
// Carries:
//
//   * Pubkey P = s·G₂ (committed at poly[0])
//   * The Pedersen / Feldman commitment coefficients for the
//     degree-(k-1) polynomial, so a verifier can independently
//     check any PriShare is consistent with the enrolment.
//   * Threshold (k) and Total (n) so the witness set is
//     well-defined.
//
// The struct is deliberately flat — serialisation is the
// caller's responsibility so we can adapt it to whatever wire
// format (Prisma Bytes, JSON-hex, protobuf) the integration layer
// wants.
type PublicIdentity struct {
	Threshold   int
	Total       int
	PubPoly     *share.PubPoly
}

// Pubkey returns the main signing public key P = s·G₂, which is
// the constant term of the committed polynomial. kyber exposes
// this directly via PubPoly.Commit(), which returns the evaluation
// at 0 (i.e. the constant coefficient = s·G₂).
func (p *PublicIdentity) Pubkey() kyber.Point {
	return p.PubPoly.Commit()
}

// Share is one witness's private share plus the index required to
// re-interpolate during Recover. Opaque to LBS callers; witnesses
// MUST treat it as long-lived secret material.
type Share struct {
	Private *share.PriShare
}

// Enroll performs the trusted-dealer variant of LBS setup.
//
// `secretSeed` is the 32-byte seed the agent derives from its PUF
// (the caller passes it in so the PoC is deterministic under
// tests; production would feed W5b's K_PAL directly). If nil, a
// fresh scalar is drawn from crypto/rand.
//
// Returns (public identity, n private shares). The private shares
// MUST be distributed to exactly n distinct witnesses over
// authenticated channels; the caller is responsible for
// zeroising any intermediate material on the local host before
// returning control to production code paths.
func Enroll(threshold, total int, secretSeed []byte) (*PublicIdentity, []Share, error) {
	if threshold < 1 || threshold > total {
		return nil, nil, fmt.Errorf("lbs: threshold %d outside [1, %d]", threshold, total)
	}
	if total > 256 {
		// Sanity: the BDN mask is already one byte per 8 slots and
		// we want LBS to compose with it. 256 is the firm upper
		// bound for the foreseeable future.
		return nil, nil, fmt.Errorf("lbs: total %d exceeds 256", total)
	}

	// Draw the identity secret. When the caller supplies a seed
	// we derive the scalar by hashing-then-reducing — kyber's
	// Scalar.Pick with a deterministic stream would do the same,
	// but picking via suite.RandomStream keeps the rest of the
	// code symmetric and takes the hardening-of-rand problem out
	// of our hands.
	stream := suite.RandomStream()
	if len(secretSeed) > 0 {
		// Deterministic stream derived from the seed. Uses the
		// suite's XOF so parameters stay in sync with every BLS
		// operation elsewhere in the code.
		stream = suite.XOF(secretSeed)
	}
	secret := suite.G2().Scalar().Pick(stream)

	// Build the sharing polynomial of degree threshold-1 with
	// constant term `secret`. kyber's NewPriPoly handles the
	// random coefficients.
	poly := share.NewPriPoly(suite.G2(), threshold, secret, stream)
	pubPoly := poly.Commit(nil) // default base point = G₂ generator

	shares := poly.Shares(total)
	wrapped := make([]Share, total)
	for i, sh := range shares {
		wrapped[i] = Share{Private: sh}
	}

	// Zeroise intermediates. We cannot reach into kyber's scalar
	// representation from here, but reassigning the local name to
	// a fresh zero scalar at least removes the last named
	// reference — the GC frees the backing bignum on its next
	// pass. Production code should pipe a secure allocator here.
	secret = suite.G2().Scalar().Zero()
	_ = secret
	// The polynomial itself retains the coefficients in memory
	// until GC. `poly` drops out of scope at function return.
	poly = nil
	_ = poly

	return &PublicIdentity{
		Threshold: threshold,
		Total:     total,
		PubPoly:   pubPoly,
	}, wrapped, nil
}

// PartialSign produces witness i's contribution to a signature on
// `msg`. The returned bytes include the share index (kyber's
// SigShare format), which Recover needs to reinterpolate.
func PartialSign(s Share, msg []byte) ([]byte, error) {
	if s.Private == nil {
		return nil, errors.New("lbs: nil private share")
	}
	return scheme.Sign(s.Private, msg)
}

// VerifyPartial lets a coordinator (or a peer witness in a
// gossip mode) sanity-check a partial signature before combining
// it. Returning an error here means the corresponding witness
// returned garbage; the coordinator should drop it and move on.
func VerifyPartial(id *PublicIdentity, msg, partial []byte) error {
	if id == nil {
		return errors.New("lbs: nil identity")
	}
	return scheme.VerifyPartial(id.PubPoly, msg, partial)
}

// Recover combines ≥ threshold partial signatures into the full
// BLS signature σ = s · H(msg). The returned signature verifies
// under plain BLS against PublicIdentity.Pubkey().
//
// Returns an error if fewer than threshold partials are supplied,
// if any partial fails the per-share verify, or if the
// interpolation does not match. Any caller-supplied partial that
// fails VerifyPartial is a protocol-level red flag — log it and
// exclude the offending witness from the next quorum.
func Recover(id *PublicIdentity, msg []byte, partials [][]byte) ([]byte, error) {
	if id == nil {
		return nil, errors.New("lbs: nil identity")
	}
	if len(partials) < id.Threshold {
		return nil, fmt.Errorf("lbs: need ≥ %d partials, got %d", id.Threshold, len(partials))
	}
	return scheme.Recover(id.PubPoly, msg, partials, id.Threshold, id.Total)
}

// Verify is the final check a control plane runs against any
// LBS-signed message. Identical to plain BLS verify on G1/G2.
func Verify(id *PublicIdentity, msg, sig []byte) error {
	if id == nil {
		return errors.New("lbs: nil identity")
	}
	return blsScheme.Verify(id.Pubkey(), msg, sig)
}

// PubkeyBytes is the canonical 96-byte serialisation of the
// aggregate pubkey, suitable for a Prisma Bytes column or a
// protobuf field.
func (p *PublicIdentity) PubkeyBytes() ([]byte, error) {
	return p.Pubkey().MarshalBinary()
}
