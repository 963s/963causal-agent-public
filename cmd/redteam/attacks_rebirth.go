package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/963causal/agent/internal/daq"
	"github.com/963causal/agent/internal/rebirth"
)

// -----------------------------------------------------------------
// RT-017 — Phoenix rebirth: identity survives hardware failure
//          without breaking the audit chain
// -----------------------------------------------------------------
// Hypothesis: 963causal's claim that "K_PAL is silicon-bound and
// never backed up" makes the system brittle — the first CPU
// failure kills the logical service identity, defeating any
// 99.999 % availability promise.
//
// Defence (ADR-014): separate HARDWARE IDENTITY (PUF-bound, dies
// with the silicon — correctly) from SERVICE IDENTITY (LBS-
// distributed across witnesses, survives any number of hardware
// failures). The Phoenix protocol transfers the H ↔ S binding
// from the deceased H₁ to a replacement H₂ after:
//
//   * the operator signs a rebirth request with a pinned key,
//   * ≥ k witnesses attest after a mandatory cool-down,
//   * the lineage is recorded append-only.
//
// RT-017 fires six attacks that cover every way an adversary
// might abuse the protocol:
//
//   a. Unpinned operator — reject at VerifyOperator
//   b. Below-threshold attestations — reject at Execute
//   c. Cool-down not elapsed — reject at Execute
//   d. Replayed attestation from a different request — reject
//      at signature check
//   e. Duplicate witness submitting k copies — reject at
//      Execute
//   f. Spliced lineage chain — reject at VerifyLineage
func (s *Suite) RT017_PhoenixRebirthProtocolSound() Finding {
	f := Finding{
		ID:         "RT-017",
		Name:       "Phoenix: rebirth protocol survives HW failure, rejects 6 abuse paths",
		Category:   "identity-continuity",
		Hypothesis: "attacker hijacks service S by forging a rebirth request during the hardware-failure window",
		Defence:    "pinned operator key + ≥ k witness attestations + mandatory cool-down + append-only lineage (ADR-014)",
		Expected:   "unpinned operator, below-k, short cool-down, replay, duplicate witness, spliced lineage all rejected",
	}

	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	pinned := [][]byte{opPub}
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Sanity: build a legit rebirth so the abuse tests have
	// real signatures to twist.
	req, err := rebirth.SealRequest("rt-017-service", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "seal request failed in harness"
		f.Evidence = err.Error()
		return f
	}
	wits := makeRebirthWitnesses(5)
	observedAt := req.RequestedAtMs + req.CoolDownMs + 1
	legitAttests := make([]rebirth.Attestation, 3)
	for i := 0; i < 3; i++ {
		a, err := rebirth.Attest(req, pinned, 1, wits[i].index, wits[i].priv,
			observedAt, 10*time.Millisecond)
		if err != nil {
			f.Verdict = Deferred
			f.Observed = "legit attest failed"
			f.Evidence = err.Error()
			return f
		}
		legitAttests[i] = *a
	}

	// Attack (a): unpinned operator.
	_, attackerOpPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedReq, _ := rebirth.SealRequest("rt-017-service", h2Pub, h1Pub, attackerOpPriv, time.Second)
	if err := rebirth.VerifyOperator(forgedReq, pinned, 1); err == nil {
		f.Verdict = Fail
		f.Observed = "unpinned operator request accepted"
		return f
	}

	// Attack (b): below-threshold (only 2 of required 3).
	if _, err := rebirth.Execute(req, legitAttests[:2], 3, observedAt+1); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "below-threshold execute accepted"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// Attack (c): cool-down not elapsed.
	if _, err := rebirth.Execute(req, legitAttests, 3, req.RequestedAtMs+1); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "cool-down bypass accepted"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// Attack (d): replay attestations onto a different request.
	h3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	evilReq, _ := rebirth.SealRequest("rt-017-service", h3Pub, h1Pub, opPriv, 10*time.Millisecond)
	if _, err := rebirth.Execute(evilReq, legitAttests, 3,
		evilReq.RequestedAtMs+evilReq.CoolDownMs+1); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "replay of attestations on a different request accepted"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// Attack (e): same witness attestation × 3.
	dupAttests := []rebirth.Attestation{legitAttests[0], legitAttests[0], legitAttests[0]}
	if _, err := rebirth.Execute(req, dupAttests, 3, observedAt+1); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "duplicate witness attestations accepted"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// Attack (f): spliced lineage — inject a record that does not
	// chain.
	r0, _ := rebirth.Execute(req, legitAttests, 3, observedAt+1)
	h4Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	spliced, _ := rebirth.SealRequest("rt-017-service", h4Pub, h3Pub, opPriv, 10*time.Millisecond)
	spliceAttests := make([]rebirth.Attestation, 3)
	spObserved := spliced.RequestedAtMs + spliced.CoolDownMs + 1
	for i := 0; i < 3; i++ {
		a, _ := rebirth.Attest(spliced, pinned, 1, wits[i].index, wits[i].priv,
			spObserved, 10*time.Millisecond)
		spliceAttests[i] = *a
	}
	r_splice, _ := rebirth.Execute(spliced, spliceAttests, 3, spObserved+1)
	lineage := []rebirth.LineageRecord{*r0, *r_splice}
	if err := rebirth.VerifyLineage(lineage, pinned, 1, 3); !errors.Is(err, rebirth.ErrRebirth) {
		f.Verdict = Fail
		f.Observed = "spliced lineage chain accepted"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	f.Verdict = Pass
	f.Observed = "all 6 abuse paths (unpinned op, below-k, early cool-down, replay, duplicate, splice) rejected"
	f.Evidence = "r0 executed cleanly; every adversarial variant ErrRebirth-rejected"
	return f
}

// -----------------------------------------------------------------
// RT-018 — Emergency Roster Recovery vs. abuse
// -----------------------------------------------------------------
// Hypothesis: an attacker who compromises k witnesses tries to
// use the emergency-recovery path as a threshold DOWNGRADE
// (normal transition wants prev.Threshold signers; emergency
// lets them rebuild the chain) — or conversely, the legitimate
// emergency path cannot be invoked even when the ceremony is
// genuinely lost.
//
// Defence (ADR-015): emergency requires a super-majority of
// current witnesses (≥ 80 %), a mandatory 24h+ waiting period
// between declaration and activation, and a signature from an
// externally-pinned announcement key that lives outside both
// the roster and the genesis ceremony.
func (s *Suite) RT018_EmergencyRosterRecovery() Finding {
	f := Finding{
		ID:         "RT-018",
		Name:       "Emergency roster recovery: super-majority + waiting + announcement",
		Category:   "roster-emergency",
		Hypothesis: "attacker with k compromised witnesses rebuilds the chain via emergency path",
		Defence:    "super-majority (4-of-5) + 24h+ waiting + externally-pinned announcement (ADR-015)",
		Expected:   "legit emergency succeeds; sub-super-majority and forged-announcement attempts fail",
	}

	genWit, genPrivs := buildWits(5)
	cerSigs, cerPrivs := buildCeremony(3)
	genesis, err := daq.SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "genesis seal failed"
		f.Evidence = err.Error()
		return f
	}
	trusted := pickPubs(cerSigs)
	if _, err := daq.VerifyChain(&daq.RosterChain{Epochs: []daq.Epoch{*genesis}}, trusted); err != nil {
		f.Verdict = Deferred
		f.Observed = "genesis verify failed"
		f.Evidence = err.Error()
		return f
	}

	// Legit announcement key (externally pinned, separate from
	// witnesses and ceremony).
	_, annPriv, _ := ed25519.GenerateKey(rand.Reader)
	const waitMs int64 = 24 * 60 * 60 * 1000

	// Happy path: 4-of-5 super-majority + waiting elapsed.
	happyEpoch, err := daq.SealEmergencyTransition(genesis, genWit, 3, waitMs+1000,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2], genPrivs[3]},
		daq.EmergencyParams{
			Declaration:     "ceremony signers unreachable",
			DeclaredAtMs:    0,
			WaitingPeriodMs: waitMs,
		},
		annPriv)
	if err != nil {
		f.Verdict = Fail
		f.Observed = "legit emergency seal failed"
		f.Evidence = err.Error()
		return f
	}
	happyChain := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, *happyEpoch}}
	if _, err := daq.VerifyChain(happyChain, trusted); err != nil {
		f.Verdict = Fail
		f.Observed = "legit emergency chain failed verify"
		f.Evidence = err.Error()
		return f
	}

	// Attack 1: 3-of-5 (below super-majority). Must fail AT seal.
	if _, err := daq.SealEmergencyTransition(genesis, genWit, 3, waitMs+1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]},
		daq.EmergencyParams{Declaration: "evil", DeclaredAtMs: 0, WaitingPeriodMs: waitMs},
		annPriv); err == nil {
		f.Verdict = Fail
		f.Observed = "sub-super-majority emergency accepted"
		f.Evidence = "threshold downgrade via emergency path"
		return f
	}

	// Attack 2: short waiting period (1h). Must fail at seal.
	if _, err := daq.SealEmergencyTransition(genesis, genWit, 3, 3600*1000,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2], genPrivs[3]},
		daq.EmergencyParams{Declaration: "rush", DeclaredAtMs: 0, WaitingPeriodMs: 3600 * 1000},
		annPriv); err == nil {
		f.Verdict = Fail
		f.Observed = "sub-24h waiting accepted"
		return f
	}

	// Attack 3: flip a byte of the announcement signature on the
	// HAPPY-PATH emergency, then verify. Must fail at
	// VerifyChain's emergency check.
	bogus := *happyEpoch
	bogus.Emergency = &daq.EmergencyParams{
		Declaration:        happyEpoch.Emergency.Declaration,
		DeclaredAtMs:       happyEpoch.Emergency.DeclaredAtMs,
		WaitingPeriodMs:    happyEpoch.Emergency.WaitingPeriodMs,
		AnnouncementPubkey: append([]byte(nil), happyEpoch.Emergency.AnnouncementPubkey...),
		AnnouncementSig:    append([]byte(nil), happyEpoch.Emergency.AnnouncementSig...),
	}
	bogus.Emergency.AnnouncementSig[0] ^= 0x01
	bogusChain := &daq.RosterChain{Epochs: []daq.Epoch{*genesis, bogus}}
	if _, err := daq.VerifyChain(bogusChain, trusted); err == nil {
		f.Verdict = Fail
		f.Observed = "forged announcement signature accepted"
		return f
	}

	f.Verdict = Pass
	f.Observed = "legit emergency verifies; 3 abuse paths (sub-super-maj, short-wait, forged-announce) rejected"
	f.Evidence = fmt.Sprintf("emergency epoch activated at %d ms with 4-of-5 current witnesses + %dh wait",
		happyEpoch.ActivatedAtMs, waitMs/(60*60*1000))
	return f
}

func makeRebirthWitnesses(n int) []struct {
	index int
	priv  ed25519.PrivateKey
} {
	out := make([]struct {
		index int
		priv  ed25519.PrivateKey
	}, n)
	for i := 0; i < n; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		out[i].index = i
		out[i].priv = priv
	}
	return out
}
