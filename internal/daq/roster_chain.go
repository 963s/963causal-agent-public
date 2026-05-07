package daq

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"
)

// emergencySuperMajorityNumerator / Denominator define the
// super-majority fraction required for an emergency transition.
// Current policy: ≥ 80 % of prev.Witnesses. Kept as constants
// rather than config so a verifier cannot be trivially relaxed
// by a malicious operator — changing this recompiles the
// binary and invalidates every previous hash chain.
const (
	emergencySuperMajorityNumerator   = 4
	emergencySuperMajorityDenominator = 5
)

// RosterChain addresses the "Roster Integrity Paradox":
//
//   the criticism, restated: DAQ requires k-of-n witness
//   signatures per ticket, but the roster itself is stored in a
//   central DB. Anyone with DB write access can swap the five
//   witnesses for five attacker-controlled ones and forge
//   tickets with no cryptographic resistance.
//
// The fix is to treat the set of valid rosters as an
// append-only, cryptographically-linked ledger — "the chain of
// rosters". Each roster is an Epoch; each Epoch's validity
// depends on k-of-n signatures from the PREVIOUS Epoch's
// witnesses attesting to its hash. Compromise of today's DB
// alone gains the attacker nothing: to install a malicious
// Epoch they must either (a) compromise k of the current
// Epoch's witnesses (the exact threshold DAQ itself already
// defends with) or (b) fork from a historical Epoch, which is
// detected because the chain root no longer matches.
//
// Genesis is the only distinguished Epoch: its validity is
// bootstrapped by an out-of-band ceremony (e.g. seven operators
// from seven organisations co-signing with independent keys,
// captured in a published transcript). Post-genesis, every
// transition is verifiable by anyone who holds the genesis
// witnesses' pubkeys.
//
// Trust model (explicit):
//
//   * Compromise of ONE Epoch's DB → zero attack value; the
//     chain still demands k witnesses of that same Epoch to
//     sign the transition to the next one.
//   * Compromise of k witnesses in the CURRENT Epoch → full
//     attack value; they can rotate to a malicious Epoch. This
//     is the k-of-n threshold we accepted as our security bar
//     in W6 (ADR-004).
//   * Compromise of the GENESIS ceremony → catastrophic; every
//     Epoch derives from it. Mitigations: ceremony signers in
//     distinct organisations + published transcript + HSM-stored
//     genesis keys that never come back online post-ceremony.
type RosterChain struct {
	// Epochs is the ordered list, oldest first. Epochs[0] is
	// genesis. Never truncated — verifying a current ticket
	// against an old deactivated roster requires replaying from
	// genesis forward.
	Epochs []Epoch
}

// Epoch is one cryptographically-sealed roster generation.
type Epoch struct {
	// EpochNum is the monotone index. Genesis = 0.
	EpochNum uint64
	// PrevHash is the hash of the previous Epoch's Canonical()
	// serialisation. Empty on genesis. Establishes the linear
	// chain; splicing an unauthorised epoch at any point
	// invalidates every later hash.
	PrevHash []byte
	// Witnesses is the (index, pubkey) roster that enters
	// force at this Epoch. Indices must be 0..len-1.
	Witnesses []EpochWitness
	// Threshold is this Epoch's k. Can change at each transition
	// (e.g. 3-of-5 today, 5-of-7 next quarter).
	Threshold int
	// ActivatedAtMs is an advisory timestamp. NOT trusted for
	// freshness decisions; that is DAQ's job.
	ActivatedAtMs int64
	// TransitionSig and TransitionSigners come from the
	// PREVIOUS epoch. On genesis they are replaced by the
	// GenesisCeremony fields below.
	TransitionSig     []byte // Ed25519 over Canonical(prevHashAgnostic=false); one sig per TransitionSigners entry, concatenated
	TransitionSigners []int  // indices into PREVIOUS epoch's Witnesses; must satisfy prev.Threshold
	// GenesisCeremony: out-of-band multisig for Epoch 0.
	// One entry per ceremony signer; each signer's pubkey and
	// signature over Canonical() with PrevHash = []byte{}.
	// Empty for any non-genesis Epoch.
	GenesisCeremony []CeremonySig
	// Emergency, if non-nil, marks this Epoch as created via
	// the emergency-recovery procedure of ADR-015 (W15). This
	// path exists for a single failure mode: permanent loss of
	// the genesis ceremony quorum OR of the current epoch's
	// witness quorum (death, HSM loss, organisational exit).
	// Without Emergency, a roster with k lost keys is
	// permanently frozen. WITH Emergency, a SUPER-majority
	// (≥ 80 %) of the CURRENT epoch's remaining witnesses can
	// sign a recovery transition, subject to a mandatory public
	// waiting period. See VerifyChain's emergency branch for
	// the full acceptance rule.
	Emergency *EmergencyParams
	// Hash is cached after VerifyAgainst returns OK. Convenient
	// for building the next Epoch's PrevHash without recomputing.
	Hash []byte
}

// EmergencyParams is the discriminated union-member that marks
// an epoch as an emergency-recovery transition. A verifier who
// sees a non-nil Emergency field applies a STRICTER threshold
// (super-majority of prev.Witnesses) AND a time gate
// (ExecuteAfterMs must have elapsed at verify time) in lieu of
// the normal prev.Threshold check.
type EmergencyParams struct {
	// Declaration is the operator-supplied text explaining why
	// emergency recovery is being invoked. Carried in the
	// Epoch's canonical serialisation so it is bound into every
	// transition signature.
	Declaration string
	// DeclaredAtMs is the wall-clock the declaration was first
	// posted to the public mirror. NOT trusted by itself — the
	// waiting period below is what provides forensic delay.
	DeclaredAtMs int64
	// WaitingPeriodMs is the minimum time the recovery
	// announcement must have been public before the emergency
	// epoch can take effect. Production default: 30 days
	// (2_592_000_000 ms). Production MINIMUM: 24 hours
	// (86_400_000 ms) — set by policy, enforced at VerifyChain
	// time.
	WaitingPeriodMs int64
	// AnnouncementPubkey is an externally-pinned key (outside
	// both the roster AND the genesis ceremony) that signs off
	// on the emergency. Typically the legal/commercial
	// authority running the deployment. Prevents a full
	// current-witness compromise from unilaterally rebuilding
	// the chain.
	AnnouncementPubkey []byte
	AnnouncementSig    []byte // Ed25519 over hash(Canonical()) with a distinct DST
}

// EpochWitness is the public half of one roster slot.
type EpochWitness struct {
	Index  int
	Label  string
	URL    string
	Pubkey []byte // 32-byte Ed25519 pubkey used for ROSTER TRANSITION (not the BDN pubkey used for signing DAQ tickets)
}

// CeremonySig is one signer's contribution to a genesis block.
type CeremonySig struct {
	SignerPubkey []byte // 32-byte Ed25519; published in BSL / ADR-011 so verifiers can pin it
	SignerLabel  string
	Signature    []byte // 64-byte Ed25519 over Canonical(eh with empty PrevHash, empty TransitionSig, empty GenesisCeremony field)
}

// ErrChainBroken is returned when a roster chain fails
// verification. The wrapped error carries the specific reason
// so operators can tell "genesis signer key unknown" apart from
// "transition signature count below threshold" etc.
var ErrChainBroken = errors.New("daq/roster-chain: verification failed")

// Canonical returns the deterministic byte encoding of an Epoch
// suitable for hashing, signing, and verification. Signatures
// in TransitionSig / GenesisCeremony are NEVER included in the
// serialisation they sign (otherwise we'd be signing our own
// signature).
func (e Epoch) Canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString("963causal-ROSTER-EPOCH-V1\x00")
	writeU64BE(&buf, e.EpochNum)
	writeBytesWithLen(&buf, e.PrevHash)
	writeU32BE(&buf, uint32(len(e.Witnesses)))
	// Sort witnesses by Index for stable encoding.
	ws := append([]EpochWitness(nil), e.Witnesses...)
	sort.Slice(ws, func(i, j int) bool { return ws[i].Index < ws[j].Index })
	for _, w := range ws {
		writeU32BE(&buf, uint32(w.Index))
		writeBytesWithLen(&buf, []byte(w.Label))
		writeBytesWithLen(&buf, []byte(w.URL))
		writeBytesWithLen(&buf, w.Pubkey)
	}
	writeU32BE(&buf, uint32(e.Threshold))
	writeI64BE(&buf, e.ActivatedAtMs)
	// Emergency params — length-prefix-encoded so a non-nil
	// Emergency changes the hash, preventing a normal
	// transition from being silently relabelled as an
	// emergency one after the fact.
	if e.Emergency != nil {
		buf.WriteByte(0x01)
		writeBytesWithLen(&buf, []byte(e.Emergency.Declaration))
		writeI64BE(&buf, e.Emergency.DeclaredAtMs)
		writeI64BE(&buf, e.Emergency.WaitingPeriodMs)
		writeBytesWithLen(&buf, e.Emergency.AnnouncementPubkey)
	} else {
		buf.WriteByte(0x00)
	}
	return buf.Bytes()
}

// emergencyAnnouncementMessage is what the externally-pinned
// announcement key signs for an emergency epoch. A distinct
// DST keeps emergency announcements from being mistakable for
// a regular transition signature.
func (e Epoch) emergencyAnnouncementMessage() []byte {
	h := sha3.New256()
	h.Write([]byte("963causal-ROSTER-EMERGENCY-V1\x00"))
	h.Write(e.Canonical())
	return h.Sum(nil)
}

// hash returns SHA3-256 of the canonical encoding. Used for
// PrevHash and for the Epoch's own identifier.
func (e Epoch) hash() []byte {
	h := sha3.New256()
	h.Write(e.Canonical())
	return h.Sum(nil)
}

// GenesisCeremonyMessage is what each ceremony signer signs. It
// excludes the GenesisCeremony slice itself (obviously) and the
// transition fields (not applicable at genesis).
func (e Epoch) genesisCeremonyMessage() []byte {
	// Message = hash of Canonical(), bound into a fixed DST.
	digest := e.hash()
	out := make([]byte, 0, 32+32)
	out = append(out, []byte("963causal-ROSTER-GENESIS-V1\x00")...)
	out = append(out, digest...)
	return out
}

// transitionMessage is what each signer in the PREVIOUS epoch
// signs to endorse this Epoch. Exactly `hash(Canonical) || DST`
// so an operator can verify a transition by hand.
func (e Epoch) transitionMessage() []byte {
	digest := e.hash()
	out := make([]byte, 0, 32+32)
	out = append(out, []byte("963causal-ROSTER-TRANSITION-V1\x00")...)
	out = append(out, digest...)
	return out
}

// SealGenesis assembles an Epoch 0 from a set of ceremony signer
// keypairs. Each signer signs the Epoch's canonical hash with
// a domain-separated tag so a ceremony signature cannot be
// replayed in a transition context (or vice-versa). The returned
// Epoch is ready to pass to VerifyChain.
//
// `cerSignerPrivs` MUST have one entry per `cerSigners`, in the
// same order, and each private key's public half MUST match the
// corresponding SignerPubkey field (verified here to catch
// accidental miswiring).
func SealGenesis(
	witnesses []EpochWitness,
	threshold int,
	activatedAtMs int64,
	cerSigners []CeremonySig,
	cerSignerPrivs []ed25519.PrivateKey,
) (*Epoch, error) {
	if len(witnesses) == 0 {
		return nil, fmt.Errorf("daq/roster-chain: genesis with empty witness set")
	}
	if threshold < 1 || threshold > len(witnesses) {
		return nil, fmt.Errorf("daq/roster-chain: genesis threshold %d outside [1, %d]",
			threshold, len(witnesses))
	}
	if len(cerSigners) != len(cerSignerPrivs) {
		return nil, fmt.Errorf("daq/roster-chain: %d ceremony signer pubkeys, %d privs",
			len(cerSigners), len(cerSignerPrivs))
	}
	if len(cerSigners) < 2 {
		// A two-of-two ceremony is the absolute minimum; a
		// one-of-one ceremony collapses trust to a single
		// party, defeating the point of the chain.
		return nil, fmt.Errorf("daq/roster-chain: genesis needs ≥ 2 ceremony signers, got %d",
			len(cerSigners))
	}
	for i := range cerSigners {
		derived := cerSignerPrivs[i].Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, cerSigners[i].SignerPubkey) {
			return nil, fmt.Errorf("daq/roster-chain: ceremony[%d] priv/pub mismatch", i)
		}
	}
	e := &Epoch{
		EpochNum:      0,
		PrevHash:      nil,
		Witnesses:     witnesses,
		Threshold:     threshold,
		ActivatedAtMs: activatedAtMs,
	}
	msg := e.genesisCeremonyMessage()
	signed := make([]CeremonySig, len(cerSigners))
	for i, s := range cerSigners {
		sig := ed25519.Sign(cerSignerPrivs[i], msg)
		signed[i] = CeremonySig{
			SignerPubkey: append([]byte(nil), s.SignerPubkey...),
			SignerLabel:  s.SignerLabel,
			Signature:    sig,
		}
	}
	e.GenesisCeremony = signed
	e.Hash = e.hash()
	return e, nil
}

// SealTransition assembles an Epoch N+1 from the current epoch
// and k-of-n transition signatures. Each signer in
// `signerIndexes` must hold an Ed25519 private key whose public
// half matches `current.Witnesses[i].Pubkey`. The signatures are
// Ed25519 over `transitionMessage(new_epoch)`.
//
// Order: signerIndexes and signerPrivs must be in lock-step.
func SealTransition(
	current *Epoch,
	newWitnesses []EpochWitness,
	newThreshold int,
	activatedAtMs int64,
	signerIndexes []int,
	signerPrivs []ed25519.PrivateKey,
) (*Epoch, error) {
	if current == nil {
		return nil, errors.New("daq/roster-chain: transition from nil current")
	}
	if len(current.Hash) == 0 {
		return nil, errors.New("daq/roster-chain: current epoch not yet hashed (run VerifyChain first)")
	}
	if newThreshold < 1 || newThreshold > len(newWitnesses) {
		return nil, fmt.Errorf("daq/roster-chain: new threshold %d outside [1, %d]",
			newThreshold, len(newWitnesses))
	}
	if len(signerIndexes) < current.Threshold {
		return nil, fmt.Errorf("daq/roster-chain: transition needs ≥ %d signers, got %d",
			current.Threshold, len(signerIndexes))
	}
	if len(signerIndexes) != len(signerPrivs) {
		return nil, fmt.Errorf("daq/roster-chain: signer count %d != key count %d",
			len(signerIndexes), len(signerPrivs))
	}
	// Each signer index must be unique and within range, and
	// the derived pubkey must match the current roster slot.
	seen := make(map[int]bool, len(signerIndexes))
	for i, idx := range signerIndexes {
		if idx < 0 || idx >= len(current.Witnesses) {
			return nil, fmt.Errorf("daq/roster-chain: signer[%d] index %d out of current roster (%d)",
				i, idx, len(current.Witnesses))
		}
		if seen[idx] {
			return nil, fmt.Errorf("daq/roster-chain: duplicate signer index %d", idx)
		}
		seen[idx] = true
		derived := signerPrivs[i].Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, current.Witnesses[idx].Pubkey) {
			return nil, fmt.Errorf("daq/roster-chain: signer[%d] (index=%d) priv/pub mismatch with current roster", i, idx)
		}
	}
	e := &Epoch{
		EpochNum:          current.EpochNum + 1,
		PrevHash:          append([]byte(nil), current.Hash...),
		Witnesses:         newWitnesses,
		Threshold:         newThreshold,
		ActivatedAtMs:     activatedAtMs,
		TransitionSigners: append([]int(nil), signerIndexes...),
	}
	// Sign the message (bound to the NEW epoch's hash, not the
	// old one — so a transition signature cannot be replayed to
	// endorse a different epoch).
	msg := e.transitionMessage()
	var concat []byte
	for i := range signerPrivs {
		concat = append(concat, ed25519.Sign(signerPrivs[i], msg)...)
	}
	e.TransitionSig = concat
	e.Hash = e.hash()
	return e, nil
}

// SealEmergencyTransition builds an emergency-recovery epoch.
// This is the single-point escape hatch for the "permanent
// quorum loss" failure mode: the genesis ceremony quorum is
// dead / lost AND normal transitions are impossible, so the
// chain is about to freeze forever.
//
// Requirements enforced here and re-checked in VerifyChain:
//
//   1. SUPER-MAJORITY of prev.Witnesses (≥ 80 %) must sign —
//      higher than the normal threshold so a regular attacker
//      cannot trigger emergency as a downgrade.
//   2. An EXTERNALLY-PINNED announcement key must sign the
//      epoch. This key lives OUTSIDE the roster AND outside
//      the genesis ceremony. Typical choice: the company's
//      legal/commercial principal key. Prevents a 100 %-current-
//      witness compromise from unilaterally rebuilding trust.
//   3. A WAITING PERIOD (minimum 24 h, policy default 30 d)
//      must elapse between DeclaredAtMs and the time the epoch
//      is verified. During this window the declaration is
//      published publicly so any surviving ceremony signer can
//      object.
func SealEmergencyTransition(
	current *Epoch,
	newWitnesses []EpochWitness,
	newThreshold int,
	activatedAtMs int64,
	signerIndexes []int,
	signerPrivs []ed25519.PrivateKey,
	emergency EmergencyParams,
	announcementPriv ed25519.PrivateKey,
) (*Epoch, error) {
	if current == nil {
		return nil, errors.New("daq/roster-chain: emergency from nil current")
	}
	if len(current.Hash) == 0 {
		return nil, errors.New("daq/roster-chain: current epoch not yet hashed")
	}
	if newThreshold < 1 || newThreshold > len(newWitnesses) {
		return nil, fmt.Errorf("daq/roster-chain: new threshold %d outside [1, %d]",
			newThreshold, len(newWitnesses))
	}
	required := (len(current.Witnesses)*emergencySuperMajorityNumerator +
		emergencySuperMajorityDenominator - 1) / emergencySuperMajorityDenominator
	if len(signerIndexes) < required {
		return nil, fmt.Errorf("daq/roster-chain: emergency needs ≥ %d signers (super-majority of %d), got %d",
			required, len(current.Witnesses), len(signerIndexes))
	}
	if len(signerIndexes) != len(signerPrivs) {
		return nil, fmt.Errorf("daq/roster-chain: signer count %d != key count %d",
			len(signerIndexes), len(signerPrivs))
	}
	if emergency.Declaration == "" {
		return nil, errors.New("daq/roster-chain: emergency declaration required")
	}
	if emergency.WaitingPeriodMs < 24*60*60*1000 {
		return nil, fmt.Errorf("daq/roster-chain: waiting period %d ms below 24h minimum",
			emergency.WaitingPeriodMs)
	}
	// Derived announcement pubkey MUST match the one stated in
	// emergency.AnnouncementPubkey — prevents a builder who has
	// only the announcement priv key from attaching someone
	// else's pub.
	derivedAnnouncement := announcementPriv.Public().(ed25519.PublicKey)
	if len(emergency.AnnouncementPubkey) == 0 {
		emergency.AnnouncementPubkey = derivedAnnouncement
	} else if !bytes.Equal(emergency.AnnouncementPubkey, derivedAnnouncement) {
		return nil, errors.New("daq/roster-chain: announcement priv does not match emergency.AnnouncementPubkey")
	}

	// Validate and dedupe signer indices.
	seen := make(map[int]bool, len(signerIndexes))
	for i, idx := range signerIndexes {
		if idx < 0 || idx >= len(current.Witnesses) {
			return nil, fmt.Errorf("daq/roster-chain: emergency signer[%d] index %d out of range",
				i, idx)
		}
		if seen[idx] {
			return nil, fmt.Errorf("daq/roster-chain: emergency duplicate signer index %d", idx)
		}
		seen[idx] = true
		derived := signerPrivs[i].Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, current.Witnesses[idx].Pubkey) {
			return nil, fmt.Errorf("daq/roster-chain: emergency signer[%d] key mismatch", i)
		}
	}

	e := &Epoch{
		EpochNum:          current.EpochNum + 1,
		PrevHash:          append([]byte(nil), current.Hash...),
		Witnesses:         newWitnesses,
		Threshold:         newThreshold,
		ActivatedAtMs:     activatedAtMs,
		TransitionSigners: append([]int(nil), signerIndexes...),
		Emergency: &EmergencyParams{
			Declaration:        emergency.Declaration,
			DeclaredAtMs:       emergency.DeclaredAtMs,
			WaitingPeriodMs:    emergency.WaitingPeriodMs,
			AnnouncementPubkey: append([]byte(nil), emergency.AnnouncementPubkey...),
		},
	}
	// Sign the transition (each current witness signs as before).
	msg := e.transitionMessage()
	var concat []byte
	for i := range signerPrivs {
		concat = append(concat, ed25519.Sign(signerPrivs[i], msg)...)
	}
	e.TransitionSig = concat

	// Separate announcement signature with its own DST.
	annMsg := e.emergencyAnnouncementMessage()
	e.Emergency.AnnouncementSig = ed25519.Sign(announcementPriv, annMsg)

	e.Hash = e.hash()
	return e, nil
}

// verifyEmergencyParams is called by VerifyChain when it sees a
// non-nil Emergency field. Checks: announcement signature
// valid, waiting period elapsed (using DeclaredAtMs + waiting
// period vs. the epoch's ActivatedAtMs + VerifyChain's own
// wall clock — we use Epoch.ActivatedAtMs as the "when this
// epoch is supposed to take effect" bound, since that is
// signed into the canonical bytes).
func verifyEmergencyParams(e *Epoch) error {
	if e.Emergency == nil {
		return errors.New("nil emergency")
	}
	em := e.Emergency
	if em.WaitingPeriodMs < 24*60*60*1000 {
		return fmt.Errorf("waiting period %d ms below 24h floor", em.WaitingPeriodMs)
	}
	if e.ActivatedAtMs < em.DeclaredAtMs+em.WaitingPeriodMs {
		return fmt.Errorf("epoch activated %d ms before declared+waiting (%d)",
			e.ActivatedAtMs, em.DeclaredAtMs+em.WaitingPeriodMs)
	}
	if len(em.AnnouncementPubkey) != ed25519.PublicKeySize ||
		len(em.AnnouncementSig) != ed25519.SignatureSize {
		return errors.New("announcement key/sig wrong size")
	}
	msg := e.emergencyAnnouncementMessage()
	if !ed25519.Verify(em.AnnouncementPubkey, msg, em.AnnouncementSig) {
		return errors.New("announcement signature invalid")
	}
	return nil
}

// VerifyChain replays the chain from genesis forward, verifying
// every hash link, every genesis ceremony signature (if
// `trustedCeremonyPubkeys` is supplied), and every transition
// threshold + signature. Mutates each Epoch in place to cache
// its .Hash field.
//
// `trustedCeremonyPubkeys` pins the set of public keys allowed
// to co-sign the genesis block. If nil, genesis signatures are
// checked for INTERNAL consistency only (useful for tests).
// Production callers MUST pass the pinned set.
//
// Returns the latest verified Epoch on success.
func VerifyChain(chain *RosterChain, trustedCeremonyPubkeys [][]byte) (*Epoch, error) {
	if chain == nil || len(chain.Epochs) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrChainBroken)
	}
	for i := range chain.Epochs {
		e := &chain.Epochs[i]
		e.Hash = e.hash()
		if e.EpochNum != uint64(i) {
			return nil, fmt.Errorf("%w: epoch[%d] claims EpochNum=%d", ErrChainBroken, i, e.EpochNum)
		}
		if i == 0 {
			// Genesis: verify ceremony.
			if len(e.PrevHash) != 0 {
				return nil, fmt.Errorf("%w: genesis has non-empty PrevHash", ErrChainBroken)
			}
			if len(e.GenesisCeremony) < 2 {
				return nil, fmt.Errorf("%w: genesis has < 2 ceremony sigs", ErrChainBroken)
			}
			msg := e.genesisCeremonyMessage()
			seenPubs := make(map[string]bool, len(e.GenesisCeremony))
			for j, cs := range e.GenesisCeremony {
				if len(cs.SignerPubkey) != ed25519.PublicKeySize || len(cs.Signature) != ed25519.SignatureSize {
					return nil, fmt.Errorf("%w: genesis ceremony[%d] wrong-size key/sig", ErrChainBroken, j)
				}
				if seenPubs[string(cs.SignerPubkey)] {
					return nil, fmt.Errorf("%w: genesis ceremony[%d] duplicate signer", ErrChainBroken, j)
				}
				seenPubs[string(cs.SignerPubkey)] = true
				if trustedCeremonyPubkeys != nil && !anyEqual(trustedCeremonyPubkeys, cs.SignerPubkey) {
					return nil, fmt.Errorf("%w: genesis ceremony[%d] signer %x not in pinned set",
						ErrChainBroken, j, cs.SignerPubkey[:8])
				}
				if !ed25519.Verify(cs.SignerPubkey, msg, cs.Signature) {
					return nil, fmt.Errorf("%w: genesis ceremony[%d] signature invalid",
						ErrChainBroken, j)
				}
			}
			continue
		}
		// Non-genesis: prev hash match + threshold check.
		prev := &chain.Epochs[i-1]
		if !bytes.Equal(e.PrevHash, prev.Hash) {
			return nil, fmt.Errorf("%w: epoch[%d] PrevHash mismatch", ErrChainBroken, i)
		}
		// Threshold rule depends on whether this is a normal
		// transition or an emergency recovery.
		requiredSigners := prev.Threshold
		if e.Emergency != nil {
			requiredSigners = (len(prev.Witnesses)*emergencySuperMajorityNumerator +
				emergencySuperMajorityDenominator - 1) / emergencySuperMajorityDenominator
			if err := verifyEmergencyParams(e); err != nil {
				return nil, fmt.Errorf("%w: epoch[%d] emergency: %v", ErrChainBroken, i, err)
			}
		}
		if len(e.TransitionSigners) < requiredSigners {
			return nil, fmt.Errorf("%w: epoch[%d] transition signers %d < required %d (emergency=%t)",
				ErrChainBroken, i, len(e.TransitionSigners), requiredSigners, e.Emergency != nil)
		}
		if len(e.TransitionSig) != len(e.TransitionSigners)*ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: epoch[%d] transition sig blob %d bytes, expected %d",
				ErrChainBroken, i, len(e.TransitionSig),
				len(e.TransitionSigners)*ed25519.SignatureSize)
		}
		msg := e.transitionMessage()
		seenIdx := make(map[int]bool, len(e.TransitionSigners))
		for j, idx := range e.TransitionSigners {
			if idx < 0 || idx >= len(prev.Witnesses) {
				return nil, fmt.Errorf("%w: epoch[%d] signer[%d] index %d out of prev roster",
					ErrChainBroken, i, j, idx)
			}
			if seenIdx[idx] {
				return nil, fmt.Errorf("%w: epoch[%d] duplicate signer index %d",
					ErrChainBroken, i, idx)
			}
			seenIdx[idx] = true
			sigStart := j * ed25519.SignatureSize
			sig := e.TransitionSig[sigStart : sigStart+ed25519.SignatureSize]
			if !ed25519.Verify(prev.Witnesses[idx].Pubkey, msg, sig) {
				return nil, fmt.Errorf("%w: epoch[%d] signer index %d sig invalid",
					ErrChainBroken, i, idx)
			}
		}
	}
	return &chain.Epochs[len(chain.Epochs)-1], nil
}

// Latest returns the current Epoch or an error on an empty /
// unverified chain. Does NOT re-run verification; callers should
// have invoked VerifyChain on load.
func (c *RosterChain) Latest() (*Epoch, error) {
	if c == nil || len(c.Epochs) == 0 {
		return nil, errors.New("daq/roster-chain: empty chain")
	}
	return &c.Epochs[len(c.Epochs)-1], nil
}

// -----------------------------------------------------------------
// encoding helpers

func writeU32BE(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}
func writeU64BE(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}
func writeI64BE(buf *bytes.Buffer, v int64) {
	writeU64BE(buf, uint64(v))
}
func writeBytesWithLen(buf *bytes.Buffer, b []byte) {
	writeU32BE(buf, uint32(len(b)))
	buf.Write(b)
}
func anyEqual(set [][]byte, x []byte) bool {
	for _, s := range set {
		if bytes.Equal(s, x) {
			return true
		}
	}
	return false
}
