package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/963causal/agent/internal/daq"
)

// -----------------------------------------------------------------
// RT-016 — "Roster Integrity Paradox": attacker owns the DB and
//          swaps in a malicious roster
// -----------------------------------------------------------------
// Hypothesis: an adversary with full control of the control-plane
// database writes any bytes they want to the roster table. The
// criticism that motivated W14 ADR-013: without a cryptographically-
// linked roster chain, such an attacker can simply publish a new
// "active" roster of 5 witnesses they own, and every subsequent
// DAQ ticket becomes a forgery.
//
// Defence (this work): `internal/daq/roster_chain.go` requires
// every Epoch transition to carry ≥ k-of-n Ed25519 signatures
// from the PREVIOUS Epoch's witnesses. Hash-chaining binds each
// Epoch to its predecessor; the Genesis Epoch is pinned by a
// multi-signer ceremony whose pubkeys are hardcoded in BSL.
// VerifyChain with the pinned pubkey set rejects any alternative
// chain an attacker with DB write access could fabricate.
//
// The harness spins up a clean genesis + one legitimate
// transition, confirms the chain verifies, then runs THREE
// attacker variants against the verifier:
//
//   a. drop-in malicious Epoch with random signatures
//   b. drop-in malicious Epoch signed by the ATTACKER'S OWN keys
//      (simulating "attacker forged a genesis ceremony")
//   c. rollback: serve a truncated chain that skips the
//      legitimate Epoch 1 to activate an earlier, now-retired
//      roster
//
// All three must be rejected. Any nil-error return is a FAIL.
func (s *Suite) RT016_RosterChainForgeryRejected() Finding {
	f := Finding{
		ID:         "RT-016",
		Name:       "Roster chain: attacker-owned DB cannot forge active roster",
		Category:   "roster-integrity",
		Hypothesis: "attacker writes arbitrary bytes to the roster table after the legitimate chain is in place",
		Defence:    "hash-chained Epochs + pinned genesis ceremony + k-of-n transition sigs from the previous Epoch",
		Expected:   "VerifyChain rejects every forgery variant (untrusted genesis, forged transition, chain splice/rollback)",
	}

	// ---- Stage 1: stand up a legitimate chain -----------------
	wits, privs := buildWits(5)
	cerSigs, cerPrivs := buildCeremony(3)
	trusted := pickPubs(cerSigs)

	genesis, err := daq.SealGenesis(wits, 3, 0, cerSigs, cerPrivs)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "legit genesis seal failed in harness"
		f.Evidence = err.Error()
		return f
	}
	epoch1, err := daq.SealTransition(genesis, wits, 3, 1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{privs[0], privs[1], privs[2]})
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "legit epoch1 seal failed"
		f.Evidence = err.Error()
		return f
	}
	honest := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, *epoch1}}
	if _, err := daq.VerifyChain(honest, trusted); err != nil {
		f.Verdict = Deferred
		f.Observed = "legit chain failed verify in harness"
		f.Evidence = err.Error()
		return f
	}

	// ---- Attack (a): attacker forges a genesis with their own
	// ceremony keys. The DB accepts anything, but the pinned
	// trusted set excludes the attacker's pubkey.
	attackerWits, _ := buildWits(5)
	attackerCer, attackerCerPrivs := buildCeremony(3)
	fakeGenesis, err := daq.SealGenesis(attackerWits, 3, 500, attackerCer, attackerCerPrivs)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "attacker genesis construction failed (harness bug)"
		return f
	}
	forgedChain := &daq.RosterChain{Epochs: []daq.Epoch{*fakeGenesis}}
	if _, err := daq.VerifyChain(forgedChain, trusted); err == nil {
		f.Verdict = Fail
		f.Observed = "attacker-forged genesis accepted despite unpinned ceremony keys"
		f.Evidence = "genesis ceremony pinning did not engage"
		return f
	}

	// ---- Attack (b): attacker tries to extend the LEGITIMATE
	// genesis with an Epoch whose transition sig is random bytes.
	bogusEpoch := *epoch1
	for i := range bogusEpoch.TransitionSig {
		bogusEpoch.TransitionSig[i] = 0xAA
	}
	bogusChain := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, bogusEpoch}}
	if _, err := daq.VerifyChain(bogusChain, trusted); err == nil {
		f.Verdict = Fail
		f.Observed = "bogus-sig epoch accepted"
		f.Evidence = "Ed25519 verify bypassed"
		return f
	}

	// ---- Attack (c): chain splice / rollback. Add a second
	// legitimate transition then drop the middle one.
	epoch2, _ := daq.SealTransition(epoch1, wits, 3, 2000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{privs[0], privs[1], privs[2]})
	truncated := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, *epoch2}}
	if _, err := daq.VerifyChain(truncated, trusted); err == nil {
		f.Verdict = Fail
		f.Observed = "truncated chain (splice) accepted"
		f.Evidence = "hash chain verification bypassed"
		return f
	}

	// ---- Attack (d): under-threshold transition. Attacker
	// compromised ONE legitimate witness and tries to pass the
	// rotation with just that one signature.
	underThresh, err := daq.SealTransition(genesis, wits, 3, 1500,
		[]int{0}, []ed25519.PrivateKey{privs[0]})
	if err == nil {
		// SealTransition refused at construction time? Good; but
		// an adversarial forger could skip our Seal helper and
		// write any bytes. Simulate that.
		_ = underThresh
	}
	// Simulate raw forgery by editing Signers / Sig blob directly.
	underThresh = epoch1 // start from a legitimate epoch
	underThreshCopy := *underThresh
	underThreshCopy.TransitionSigners = []int{0}
	underThreshCopy.TransitionSig = underThresh.TransitionSig[:ed25519.SignatureSize]
	underChain := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, underThreshCopy}}
	if _, err := daq.VerifyChain(underChain, trusted); err == nil {
		f.Verdict = Fail
		f.Observed = "under-threshold transition accepted"
		f.Evidence = "threshold check bypassed"
		return f
	}

	f.Verdict = Pass
	f.Observed = "all four DB-write attacks rejected by the roster chain"
	f.Evidence = fmt.Sprintf("genesis ceremony = %d pinned sigs, epoch threshold = %d",
		len(genesis.GenesisCeremony), genesis.Threshold)
	return f
}

// -----------------------------------------------------------------

func buildWits(n int) ([]daq.EpochWitness, []ed25519.PrivateKey) {
	ws := make([]daq.EpochWitness, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		ws[i] = daq.EpochWitness{
			Index:  i,
			Label:  fmt.Sprintf("rt016-w%d", i),
			URL:    fmt.Sprintf("http://127.0.0.1:%d", 18000+i),
			Pubkey: pub,
		}
		privs[i] = priv
	}
	return ws, privs
}

func buildCeremony(n int) ([]daq.CeremonySig, []ed25519.PrivateKey) {
	cs := make([]daq.CeremonySig, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		cs[i] = daq.CeremonySig{
			SignerPubkey: pub,
			SignerLabel:  fmt.Sprintf("rt016-ceremony-%d", i),
		}
		privs[i] = priv
	}
	return cs, privs
}

func pickPubs(sigs []daq.CeremonySig) [][]byte {
	out := make([][]byte, len(sigs))
	for i, s := range sigs {
		out[i] = s.SignerPubkey
	}
	return out
}
