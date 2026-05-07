package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/963causal/agent/internal/qee"
	"github.com/963causal/agent/internal/rebirth"
	"golang.org/x/crypto/nacl/box"
)

// -----------------------------------------------------------------
// RT-019 — Amnesiac Phoenix Paradox: data survives H₁ death,
//          no master key exists
// -----------------------------------------------------------------
// Hypothesis: the W15 memo pointed out a real flaw — Phoenix
// transfers the identity S but said NOTHING about the data
// encrypted under K_PAL₁ on H₁. If recovery requires a
// "master key", the silicon binding is theatre.
//
// Defence (ADR-017): Quorum Envelope Encryption. Every sealed
// payload carries TWO independent DEK wrappers:
//   (1) SiliconWrap: NaCl box from a one-shot ephemeral to
//       the host's K_PAL-derived X25519 pub (fast path).
//   (2) WitnessShares: Shamir-split DEK, one NaCl box per
//       witness long-term X25519 pub (recovery path).
// There is NO third "master key" copy. Recovery requires k
// witnesses to each decrypt their own share.
//
// RT-019 confirms:
//
//   a. H₁ can open its own data (happy fast path).
//   b. With k witness shares, H₂ can recover AND rebind to
//      its own silicon.
//   c. With ONLY k-1 witness shares, RecoverDEK refuses.
//   d. An adversary who compromises 1 witness reconstructs
//      a WRONG DEK that cannot open the AEAD.
//   e. An adversary who edits the stored threshold trips the
//      AEAD's authenticated-data check.
func (s *Suite) RT019_QEEAmnesiaSurvivable() Finding {
	f := Finding{
		ID:         "RT-019",
		Name:       "QEE: data recoverable across HW failure without master key",
		Category:   "data-continuity",
		Hypothesis: "attacker with DB + operator key + k-1 witnesses can decrypt H₁'s sealed data",
		Defence:    "Shamir-split DEK + per-witness NaCl box + AEAD-bound (n, k) header (ADR-017)",
		Expected:   "fast-path works on H₁; k-of-n recovery re-binds to H₂; below-k and 1-witness and threshold-tamper all fail",
	}

	// ---- Setup ----
	h1Pub, h1Priv := genQeeKeys()
	witnesses, witPrivs := genQeeWitnesses(5)
	plaintext := []byte("RT-019 canary payload — should survive H1 death via k-of-n recovery")

	env, err := qee.Seal(plaintext, h1Pub, witnesses, 3)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "qee.Seal failed in harness"
		f.Evidence = err.Error()
		return f
	}

	// (a) Happy fast path: H₁ opens directly.
	got, err := qee.OpenSilicon(env, h1Pub, h1Priv)
	if err != nil || !bytes.Equal(got, plaintext) {
		f.Verdict = Fail
		f.Observed = "H1 silicon fast path failed to open its own seal"
		if err != nil {
			f.Evidence = err.Error()
		}
		return f
	}

	// (b) Recovery path: k witnesses unbox their shares, DEK
	// recovered, resealed to H₂, H₂ opens.
	h2Pub, h2Priv := genQeeKeys()
	shares := make([]qee.Share, 3)
	for i := 0; i < 3; i++ {
		share, err := qee.WitnessUnboxShare(env.WitnessShares[i],
			witnesses[i].Pubkey, witPrivs[i])
		if err != nil {
			f.Verdict = Fail
			f.Observed = "witness unbox failed"
			f.Evidence = err.Error()
			return f
		}
		shares[i] = share
	}
	dek, err := qee.RecoverDEK(env, shares)
	if err != nil {
		f.Verdict = Fail
		f.Observed = "RecoverDEK failed with k shares"
		f.Evidence = err.Error()
		return f
	}
	newEnv, err := qee.ReSeal(env, dek, h2Pub, witnesses, 3)
	if err != nil {
		f.Verdict = Fail
		f.Observed = "ReSeal to H2 failed"
		f.Evidence = err.Error()
		return f
	}
	recovered, err := qee.OpenSilicon(newEnv, h2Pub, h2Priv)
	if err != nil || !bytes.Equal(recovered, plaintext) {
		f.Verdict = Fail
		f.Observed = "H2 could not open after recovery"
		return f
	}

	// (c) Below threshold: only 2 shares when k = 3.
	if _, err := qee.RecoverDEK(env, shares[:2]); err == nil {
		f.Verdict = Fail
		f.Observed = "RecoverDEK accepted 2 shares (below k=3)"
		return f
	}

	// (d) Single-witness compromise insufficient. The attacker
	// unboxes just ONE share and tries to use it as a DEK —
	// the AEAD must reject.
	oneShare, _ := qee.WitnessUnboxShare(env.WitnessShares[0],
		witnesses[0].Pubkey, witPrivs[0])
	fakeDEK, _ := qee.Combine([]qee.Share{oneShare}, 1) // degree-0 interpolation
	evilH2Pub, evilH2Priv := genQeeKeys()
	evilEnv, _ := qee.ReSeal(env, fakeDEK, evilH2Pub, witnesses, 3)
	if _, err := qee.OpenSilicon(evilEnv, evilH2Pub, evilH2Priv); err == nil {
		f.Verdict = Fail
		f.Observed = "single-witness fake DEK opened the AEAD"
		return f
	}

	// (e) Threshold-tamper: attacker rewrites env.Threshold = 1
	// hoping the AEAD accepts. AD binds (n, k) so it fails.
	tampered := *env
	tampered.Threshold = 1
	if _, err := qee.OpenSilicon(&tampered, h1Pub, h1Priv); err == nil {
		f.Verdict = Fail
		f.Observed = "AEAD accepted tampered threshold"
		return f
	}

	f.Verdict = Pass
	f.Observed = "fast path opens; k-of-n recovery + rebind to H2 works; 3 abuse paths rejected"
	f.Evidence = fmt.Sprintf("env: n=%d k=%d data_len=%d B; no single master key",
		env.RosterSize, env.Threshold, len(env.Data))
	return f
}

// -----------------------------------------------------------------
// RT-020 — Operator-as-God: M-of-N operator rebirth threshold
// -----------------------------------------------------------------
// Hypothesis (W15 memo): Phoenix's single operator key creates a
// single point of failure. An attacker who social-engineers
// or compromises ONE operator can rebirth a service to a host
// they control.
//
// Defence (ADR-018): operator signatures are now an M-of-N set
// from a pinned principal list. Deployment policy sets M; any
// request with fewer than M distinct pinned signatures is
// rejected at VerifyOperator.
func (s *Suite) RT020_MultiOperatorRebirthThreshold() Finding {
	f := Finding{
		ID:         "RT-020",
		Name:       "Phoenix multi-operator threshold rejects single-operator compromise",
		Category:   "identity-continuity",
		Hypothesis: "attacker with ONE stolen operator key rebirths a service (bypassing M-of-N)",
		Defence:    "VerifyOperator enforces ≥ M distinct pinned operator signatures over Canonical() (ADR-018)",
		Expected:   "2-of-3 policy accepts 2 legit sigs, rejects 1 legit sig, rejects duplicated sig",
	}

	op1Pub, op1Priv, _ := ed25519.GenerateKey(rand.Reader)
	op2Pub, op2Priv, _ := ed25519.GenerateKey(rand.Reader)
	op3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pinned := [][]byte{op1Pub, op2Pub, op3Pub}

	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// (a) Legit 2-of-3 must pass.
	req2, _ := rebirth.SealRequestMultiOp("rt-020-service", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv, op2Priv}, 10*time.Millisecond)
	if err := rebirth.VerifyOperator(req2, pinned, 2); err != nil {
		f.Verdict = Fail
		f.Observed = "legit 2-of-3 rejected"
		f.Evidence = err.Error()
		return f
	}

	// (b) Attacker with ONE stolen key tries to rebirth. The
	// deployment policy is M = 2. Must fail.
	req1, _ := rebirth.SealRequestMultiOp("rt-020-service", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv}, 10*time.Millisecond)
	if err := rebirth.VerifyOperator(req1, pinned, 2); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "single-operator compromise accepted under M=2"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// (c) Attacker duplicates op1's signature to fake M=2.
	reqDup := *req1
	reqDup.OperatorSignatures = append(reqDup.OperatorSignatures,
		reqDup.OperatorSignatures[0])
	if err := rebirth.VerifyOperator(&reqDup, pinned, 2); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "duplicate-signer attack accepted"
		return f
	}

	// (d) Attacker includes an unpinned operator's sig.
	_, rogueOpPriv, _ := ed25519.GenerateKey(rand.Reader)
	reqRogue, _ := rebirth.SealRequestMultiOp("rt-020-service", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv, rogueOpPriv}, 10*time.Millisecond)
	if err := rebirth.VerifyOperator(reqRogue, pinned, 2); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "rogue (unpinned) operator signature accepted"
		return f
	}

	f.Verdict = Pass
	f.Observed = "2-of-3 legit pass; 1-of-3 reject; duplicate reject; rogue-op reject"
	f.Evidence = "M-of-N threshold enforces distinct + pinned operator signatures"
	return f
}

// -----------------------------------------------------------------

func genQeeKeys() (pub, priv [32]byte) {
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return *p, *s
}

func genQeeWitnesses(n int) ([]qee.WitnessPubkey, [][32]byte) {
	pubs := make([]qee.WitnessPubkey, n)
	privs := make([][32]byte, n)
	for i := 0; i < n; i++ {
		p, s, _ := box.GenerateKey(rand.Reader)
		pubs[i] = qee.WitnessPubkey{Index: i, Pubkey: *p}
		privs[i] = *s
	}
	return pubs, privs
}
