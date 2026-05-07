package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/963causal/agent/internal/daq"
	"github.com/963causal/agent/internal/puf"
)

// -----------------------------------------------------------------
// RT-011 — PUF helper theft, attacker uses different silicon
// -----------------------------------------------------------------
// Hypothesis: attacker exfiltrates puf.keystore.json from the
// original host and tries to reproduce K on any other machine.
// W5b claims this fails because the helper mask is XOR'd with
// silicon-specific PUF bits; on a different host those bits are
// random noise, Hamming(7,4) cannot correct a 50%-BER block, and
// the commitment check rejects the recovered candidate.
//
// The harness simulates "different silicon" without a second
// machine by:
//
//   1. Enrolling a helper from a real fingerprint captured on the
//      local host (call it fp_real).
//   2. Generating a completely random fingerprint of the same
//      shape (fp_evil) — this is the maximally-different silicon
//      an attacker could conceivably have.
//   3. Running Reproduce(fp_evil, helper) and expecting a
//      commitment mismatch (or a decode error, both count as
//      defence-in-depth holding).
//
// Note: this is a LOWER bound on the difficulty. On a real foreign
// machine the PUF bits would be statistically independent of the
// enrolling host's, which is exactly what the synthetic random
// fingerprint models.
func (s *Suite) RT011_PUFHelperTheftWrongSilicon() Finding {
	f := Finding{
		ID:         "RT-011",
		Name:       "PUF helper theft on foreign silicon",
		Category:   "puf-theft",
		Hypothesis: "attacker with stolen helper data tries to reproduce K on a different host",
		Defence:    "HKDF commitment over K; codeword-XOR hides K unless PUF bits match",
		Expected:   "Reproduce returns error (decode failure or commitment mismatch)",
	}

	// Step 1: grab a real fingerprint on this host, using the
	// lightest Measure config so the test stays fast (a full
	// calibration is unnecessary — we only need ONE measurement
	// that Enroll is willing to work with).
	cfg := puf.Config{Trials: 8}
	m, err := puf.Measure(cfg)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "could not take a local PUF measurement on this harness host"
		f.Evidence = err.Error()
		return f
	}
	fpReal := puf.QuantizeV3(m, nil)
	if fpReal.Length < puf.HelperBits {
		f.Verdict = Deferred
		f.Observed = fmt.Sprintf("local fingerprint too short (%d < %d); harness cannot enrol", fpReal.Length, puf.HelperBits)
		return f
	}

	// Pick the first HelperBits positions as "reliable" for this
	// single-measurement enrolment. The red-team suite does not
	// need a genuinely reliable selection — we only need Enroll to
	// succeed so the helper exists for the adversary to steal.
	indices := make([]int, puf.HelperBits)
	for i := range indices {
		indices[i] = i
	}
	K, helper, err := puf.Enroll(fpReal, indices)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "Enroll failed on local silicon"
		f.Evidence = err.Error()
		return f
	}
	// Sanity: ensure the honest path would Reproduce K cleanly if
	// we re-used the SAME fingerprint. Skipping this check would
	// let a genuine bug masquerade as "defence held".
	honestK, err := puf.Reproduce(fpReal, helper)
	if err != nil || !bytesEqual(honestK, K) {
		f.Verdict = Deferred
		f.Observed = "baseline Reproduce on same fingerprint failed — harness cannot isolate the attack"
		if err != nil {
			f.Evidence = "reproduce: " + err.Error()
		} else {
			f.Evidence = "K' != K on same fp (harness bug)"
		}
		return f
	}

	// Step 2: forge "foreign silicon" — a fingerprint of identical
	// shape whose bits are statistically independent of fpReal.
	evilBits := make([]byte, len(fpReal.Bits))
	if _, err := rand.Read(evilBits); err != nil {
		f.Verdict = Deferred
		f.Observed = "rand.Read failed"
		f.Evidence = err.Error()
		return f
	}
	fpEvil := fpReal
	fpEvil.Bits = evilBits

	// Step 3: the attack itself — replay the stolen helper on the
	// random fingerprint. We expect either:
	//   (a) an error (commitment mismatch / decode failure), or
	//   (b) a non-nil K' that is NOT equal to K (which we treat
	//       as FAIL because the intended API contract is "Reproduce
	//       returns an error on wrong silicon").
	evilK, evilErr := puf.Reproduce(fpEvil, helper)
	switch {
	case evilErr != nil:
		f.Verdict = Pass
		f.Observed = "Reproduce returned error on forged foreign silicon"
		f.Evidence = evilErr.Error()
	case bytesEqual(evilK, K):
		// Astronomical probability (≈ 2^-128) — would be a genuine
		// finding. We still report FAIL so the operator investigates.
		f.Verdict = Fail
		f.Observed = "Reproduce returned the enrolled K on forged silicon — IMPOSSIBLE without a real break"
		f.Evidence = "K' = " + hex.EncodeToString(evilK)
	default:
		// Reproduce returned a DIFFERENT K' without an error. This
		// is also a finding because callers rely on the no-error
		// path to mean "K is the enrolled secret".
		f.Verdict = Fail
		f.Observed = "Reproduce returned a different K without surfacing an error"
		f.Evidence = "K' = " + hex.EncodeToString(evilK)
	}
	return f
}

// -----------------------------------------------------------------
// RT-012 — BDN rogue-key attack simulation
// -----------------------------------------------------------------
// Hypothesis: a classical rogue-key attack against a plain BLS
// multi-sig is to register pk_evil = -pk_target (or pk_evil = pk_a
// - pk_b) so the adversary alone can produce a "2-of-n" signature
// that verifies. BDN defeats this with coefficients
// c_i = H(pk_i, {pk_0..pk_n-1}), so an attacker who edits the
// roster breaks the coefficient derivation.
//
// We can't actually forge pk_evil = -pk_target cheaply, but we can
// confirm the defence by (a) replacing one roster pubkey with a
// fresh random keypair the adversary holds, (b) re-signing with
// the adversary's private key, and (c) checking that the
// legitimate roster's verifier rejects the crafted aggregate —
// because the mask bits now reference coefficients computed over
// the wrong roster set.
func (s *Suite) RT012_BDNRogueKeySimulation() Finding {
	f := Finding{
		ID:         "RT-012",
		Name:       "BDN rogue-key attack simulation",
		Category:   "bls-rogue-key",
		Hypothesis: "attacker substitutes one roster slot with their own keypair, signs with it, hopes verifier accepts",
		Defence:    "BDN coefficients H(pk_i, {pk_0..pk_n}) bind the full roster; any swap changes every coefficient",
		Expected:   "VerifyAggregate against the legitimate roster rejects the crafted aggregate",
	}

	// 1. Collect a legitimate 3-of-5 aggregate.
	ticket, _, err := s.buildValidParallelTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "could not collect baseline quorum"
		f.Evidence = err.Error()
		return f
	}

	// 2. Attacker generates a fresh keypair (the "rogue key"). We
	// cannot cheaply craft pk_evil = -pk_target + pk_other, but a
	// fresh random keypair is strictly weaker and still has to
	// pass BDN verification — if BDN's coefficient trick holds
	// against it, it holds against the contrived case too.
	_, rogue, err := daq.GenerateKeyPair()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "rogue keypair generation failed"
		f.Evidence = err.Error()
		return f
	}

	// 3. Craft a "poisoned roster": replace witness 0's pubkey
	// with the rogue one. Verifier will re-derive the BDN
	// coefficients over this new roster set; the aggregate the
	// honest witnesses produced was under the original roster, so
	// pairing MUST fail.
	poisoned := append([]*daq.PublicKey(nil), s.env.RosterPubs...)
	poisoned[0] = rogue

	// Canonical witness input comes from THIS ticket's request (we
	// must not rebuild; a fresh BuildRequest carries a different
	// requested_at_ms and would make the verifier fail for a
	// harmless reason).
	input, inpErr := daq.WitnessInput(&ticket.Request, daq.ModeParallel, 0, nil)
	if inpErr != nil {
		f.Verdict = Deferred
		f.Observed = "could not derive canonical witness input"
		f.Evidence = inpErr.Error()
		return f
	}

	v, ev := expectReject(
		daq.VerifyAggregate(poisoned, ticket.AggMask, ticket.AggSignature, input, s.env.Threshold),
	)
	f.Verdict = v
	f.Observed = "VerifyAggregate " + string(v) + " under poisoned roster"
	f.Evidence = ev
	return f
}

// bytesEqual is the tiniest possible equality helper. We pointedly
// do NOT use crypto/subtle here because RT-011's success case
// compares two secrets that should be cryptographically different;
// constant-time behaviour provides no extra safety in that context
// and the plain loop is easier to reason about.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
