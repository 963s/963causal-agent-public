package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/963causal/agent/internal/daq"
)

// buildValidParallelTicket is a helper many attacks start from: run
// a clean 3-of-5 parallel quorum, return both the ticket and the
// request it carries. We never accept a tampered ticket through
// RequestQuorum (the client-side individual-verify check would drop
// it), so attacks that want a tampered ticket must tamper AFTER
// this call.
func (s *Suite) buildValidParallelTicket() (*daq.Ticket, *daq.Request, error) {
	req, err := s.env.BuildRequest("rt-parallel", []byte("rt-parallel-payload"))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	cfg := daq.ClientConfig{
		Roster:    s.env.Roster,
		Threshold: s.env.Threshold,
		Mode:      daq.ModeParallel,
		HTTP:      s.env.HTTP,
	}
	ticket, err := daq.RequestQuorum(s.ctx, cfg, req)
	if err != nil {
		return nil, nil, fmt.Errorf("request quorum: %w", err)
	}
	return ticket, req, nil
}

// buildValidSequentialTicket is the sequential-mode sibling.
func (s *Suite) buildValidSequentialTicket() (*daq.Ticket, *daq.Request, error) {
	req, err := s.env.BuildRequest("rt-sequential", []byte("rt-sequential-payload"))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	cfg := daq.ClientConfig{
		Roster:    s.env.Roster,
		Threshold: s.env.Threshold,
		Mode:      daq.ModeSequential,
		HTTP:      s.env.HTTP,
	}
	ticket, err := daq.RequestQuorum(s.ctx, cfg, req)
	if err != nil {
		return nil, nil, fmt.Errorf("request quorum: %w", err)
	}
	return ticket, req, nil
}

// -----------------------------------------------------------------
// RT-001 — DAQ aggregate signature bit-flip
// -----------------------------------------------------------------
// Hypothesis: an attacker with a valid parallel-mode ticket can
// substitute a one-bit-different BDN aggregate signature and have
// it accepted by VerifyTicket.
//
// Defence layered here: BLS12-381 G1 subgroup validation + BDN
// pairing check. A flipped bit either lands the point off the
// correct subgroup (cheap reject) or produces a signature that
// fails the pairing (more expensive but still rejected).
func (s *Suite) RT001_AggregateSigBitFlip() Finding {
	f := Finding{
		ID:         "RT-001",
		Name:       "DAQ aggregate signature bit-flip",
		Category:   "daq-forgery",
		Hypothesis: "attacker edits the BDN aggregate signature by one bit after the quorum is collected",
		Defence:    "BLS12-381 subgroup check + BDN pairing verify",
		Expected:   "VerifyTicket returns error, attack rejected",
	}
	ticket, _, err := s.buildValidParallelTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline quorum"
		f.Evidence = err.Error()
		return f
	}
	if err := daq.VerifyTicket(ticket, s.env.RosterPubs); err != nil {
		f.Verdict = Deferred
		f.Observed = "baseline verification failed before tamper"
		f.Evidence = err.Error()
		return f
	}
	// Tamper: flip the high-order bit of the aggregate.
	ticket.AggSignature[0] ^= 0x01
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " after single-bit aggregate tamper"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-002 — DAQ mask forgery, extra witness claimed
// -----------------------------------------------------------------
// Hypothesis: attacker flips a bit in the participation mask to
// claim an additional witness signed, without collecting that
// witness's signature. BDN's coefficient h(pk_i, roster) mixes
// every pubkey in the roster, so the aggregated pubkey the verifier
// reconstructs will differ from the one implicit in the aggregate
// signature → pairing fails.
func (s *Suite) RT002_MaskForgeryExtraWitness() Finding {
	f := Finding{
		ID:         "RT-002",
		Name:       "DAQ mask forgery (extra witness claimed)",
		Category:   "daq-forgery",
		Hypothesis: "attacker sets an extra bit in the participation bitmask",
		Defence:    "BDN coefficient derivation covers the whole roster, not per-bit slot",
		Expected:   "VerifyTicket returns error, aggregate does not verify",
	}
	ticket, _, err := s.buildValidParallelTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline quorum"
		f.Evidence = err.Error()
		return f
	}
	ticket.AggMask = append([]byte(nil), ticket.AggMask...)
	// Find the first unset bit and flip it.
	for i := 0; i < ticket.RosterSize; i++ {
		if ticket.AggMask[i/8]&(1<<uint(i%8)) == 0 {
			ticket.AggMask[i/8] |= 1 << uint(i%8)
			f.Evidence = fmt.Sprintf("flipped mask bit %d from 0→1", i)
			break
		}
	}
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " with forged mask"
	if v == Pass {
		f.Evidence = ev
	}
	return f
}

// -----------------------------------------------------------------
// RT-003 — DAQ mask shrink below threshold
// -----------------------------------------------------------------
// Hypothesis: attacker clears bits in the mask so fewer than k
// witnesses appear to have signed, expecting either a stale ticket
// to still verify or a downgrade attack.
//
// Defence: VerifyAggregate enforces CountEnabled() >= minParticipants.
func (s *Suite) RT003_MaskShrinkBelowThreshold() Finding {
	f := Finding{
		ID:         "RT-003",
		Name:       "DAQ mask shrink below threshold",
		Category:   "daq-downgrade",
		Hypothesis: "attacker clears mask bits hoping the verifier downgrades to a lower k",
		Defence:    "VerifyAggregate explicit CountEnabled >= minParticipants check",
		Expected:   "VerifyTicket returns error citing threshold shortfall",
	}
	ticket, _, err := s.buildValidParallelTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline quorum"
		f.Evidence = err.Error()
		return f
	}
	ticket.AggMask = append([]byte(nil), ticket.AggMask...)
	// Clear the first two set bits.
	cleared := 0
	for i := 0; i < ticket.RosterSize && cleared < 2; i++ {
		if ticket.AggMask[i/8]&(1<<uint(i%8)) != 0 {
			ticket.AggMask[i/8] &^= 1 << uint(i%8)
			cleared++
		}
	}
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " after clearing 2 mask bits"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-004 — Sequential chain reorder
// -----------------------------------------------------------------
// Hypothesis: swap the order of two witnesses in a sequential
// ticket. Each witness's signed input embeds prev_sig, so reordering
// invalidates the chain.
func (s *Suite) RT004_SequentialChainReorder() Finding {
	f := Finding{
		ID:         "RT-004",
		Name:       "DAQ sequential chain reorder",
		Category:   "daq-forgery",
		Hypothesis: "attacker swaps adjacent witnesses in a sequential-mode ticket",
		Defence:    "WitnessInput(mode=sequential) binds prev_sig for every position > 0",
		Expected:   "VerifyTicket fails at the position whose prev_sig no longer matches",
	}
	ticket, _, err := s.buildValidSequentialTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline chain"
		f.Evidence = err.Error()
		return f
	}
	if len(ticket.Witnesses) < 2 {
		f.Verdict = Deferred
		f.Observed = "chain too short to reorder"
		return f
	}
	ticket.Witnesses[0], ticket.Witnesses[1] = ticket.Witnesses[1], ticket.Witnesses[0]
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " after swapping seq[0] and seq[1]"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-005 — Sequential chain truncation
// -----------------------------------------------------------------
// Hypothesis: drop the last witness from a sequential chain, hoping
// k-1 satisfies some downgraded threshold.
func (s *Suite) RT005_SequentialChainTruncation() Finding {
	f := Finding{
		ID:         "RT-005",
		Name:       "DAQ sequential chain truncation",
		Category:   "daq-downgrade",
		Hypothesis: "attacker drops the last witness from a sequential chain below threshold",
		Defence:    "VerifyTicket explicit len(Witnesses) < threshold check",
		Expected:   "VerifyTicket returns error citing chain length shortfall",
	}
	ticket, _, err := s.buildValidSequentialTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline chain"
		f.Evidence = err.Error()
		return f
	}
	if len(ticket.Witnesses) == 0 {
		f.Verdict = Deferred
		f.Observed = "no witnesses to drop"
		return f
	}
	ticket.Witnesses = ticket.Witnesses[:len(ticket.Witnesses)-1]
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " after truncating tail witness"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-006 — op_hash tamper post-hoc
// -----------------------------------------------------------------
// Hypothesis: attacker keeps the signed agent envelope + witness
// sigs but swaps op_hash to point at a different payload (so a
// "delete host A" ticket is reused to delete host B).
//
// Defence: agent Ed25519 signature covers op_hash via
// CanonicalRequestBytes; VerifyTicket re-checks it on ingest.
func (s *Suite) RT006_OpHashTamperPostHoc() Finding {
	f := Finding{
		ID:         "RT-006",
		Name:       "DAQ op_hash tamper post-hoc",
		Category:   "daq-reuse",
		Hypothesis: "attacker swaps op_hash to repurpose a ticket for a different operation",
		Defence:    "Agent Ed25519 signature over canonical request bytes",
		Expected:   "VerifyAgentSignature returns error",
	}
	ticket, _, err := s.buildValidParallelTicket()
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not collect baseline quorum"
		f.Evidence = err.Error()
		return f
	}
	ticket.Request.OpHash = daq.HashOperationPayload([]byte("different-payload"))
	v, ev := expectReject(daq.VerifyTicket(ticket, s.env.RosterPubs))
	f.Verdict = v
	f.Observed = "VerifyTicket " + string(v) + " after swapping op_hash"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-007 — Drand round substitution
// -----------------------------------------------------------------
// Hypothesis: attacker replaces the request's drand round number
// while keeping the (stale-but-genuine) signature, hoping to pass
// the verifier's round check.
//
// Defence: VerifyDrandBeacon re-derives the message from the round
// → round mismatch ⇒ pairing failure.
func (s *Suite) RT007_DrandRoundSubstitution() Finding {
	f := Finding{
		ID:         "RT-007",
		Name:       "Drand round substitution",
		Category:   "drand-freshness",
		Hypothesis: "attacker changes the round number while keeping the valid signature",
		Defence:    "VerifyDrandBeacon re-derives SHA256(round_be) and pairs against chain pub",
		Expected:   "BLS verify fails (point does not pair to forged message)",
	}
	sigForRealRound, err := s.env.SignFakeDrand(s.env.CurrentRound)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not sign baseline round"
		f.Evidence = err.Error()
		return f
	}
	v, ev := expectReject(
		daq.VerifyDrandBeacon(s.env.CurrentRound+1, sigForRealRound, s.env.FakeChainPub),
	)
	f.Verdict = v
	f.Observed = "VerifyDrandBeacon " + string(v) + " when round supplied ≠ round signed"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-008 — Drand signature bit-flip
// -----------------------------------------------------------------
// Hypothesis: attacker MITMs the drand relay and flips a bit in
// the beacon signature, hoping the verifier trusts the relay's
// HTTPS transport.
//
// Defence: VerifyDrandBeacon does a BLS pairing check against a
// pinned chain pubkey. Tampered sig either fails subgroup check
// or fails the pairing.
func (s *Suite) RT008_DrandSigBitFlip() Finding {
	f := Finding{
		ID:         "RT-008",
		Name:       "Drand signature bit-flip (simulated MITM)",
		Category:   "drand-forgery",
		Hypothesis: "attacker poisons the relay response with a one-bit-flipped beacon sig",
		Defence:    "VerifyDrandBeacon BLS pairing against pinned G2 chain pubkey",
		Expected:   "BLS verify returns error",
	}
	sig, err := s.env.SignFakeDrand(s.env.CurrentRound)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "harness could not sign baseline round"
		f.Evidence = err.Error()
		return f
	}
	sig[0] ^= 0x01
	v, ev := expectReject(
		daq.VerifyDrandBeacon(s.env.CurrentRound, sig, s.env.FakeChainPub),
	)
	f.Verdict = v
	f.Observed = "VerifyDrandBeacon " + string(v) + " after single-bit sig tamper"
	f.Evidence = ev
	return f
}

// -----------------------------------------------------------------
// RT-009 — Witness without bearer token
// -----------------------------------------------------------------
// Hypothesis: an internet scanner probes /daq/sign with a
// well-formed payload but no Authorization header, expecting the
// witness to sign for free.
func (s *Suite) RT009_WitnessNoBearerToken() Finding {
	f := Finding{
		ID:         "RT-009",
		Name:       "Witness /daq/sign without bearer token",
		Category:   "auth-bypass",
		Hypothesis: "scanner calls /daq/sign with no Authorization header",
		Defence:    "Witness bearer-token guard (W7.B)",
		Expected:   "HTTP 401 missing bearer token",
	}
	if len(s.env.Witnesses) == 0 {
		f.Verdict = Deferred
		f.Observed = "no witnesses to probe"
		return f
	}
	addr := s.env.Witnesses[0].addr
	resp, err := doPostBody(s.ctx, s.env.HTTP, "http://"+addr+"/daq/sign", "", `{}`)
	if err != nil {
		f.Verdict = Fail
		f.Observed = "unexpected transport error"
		f.Evidence = err.Error()
		return f
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		f.Verdict = Fail
		f.Observed = fmt.Sprintf("HTTP %d (expected 401)", resp.StatusCode)
		f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
		return f
	}
	body, _ := readBody(resp)
	f.Verdict = Pass
	f.Observed = "HTTP 401 returned before any signing work"
	f.Evidence = strings.TrimSpace(body)
	return f
}

// -----------------------------------------------------------------
// RT-010 — Witness with wrong bearer token
// -----------------------------------------------------------------
// Hypothesis: attacker guesses or steals a token, hoping a lookup
// instead of a constant-time compare leaks information.
func (s *Suite) RT010_WitnessWrongBearerToken() Finding {
	f := Finding{
		ID:         "RT-010",
		Name:       "Witness /daq/sign with wrong bearer token",
		Category:   "auth-bypass",
		Hypothesis: "attacker submits a random bearer token",
		Defence:    "Witness constant-time compare against stored SHA-256(token)",
		Expected:   "HTTP 401 bad bearer token (constant-time)",
	}
	if len(s.env.Witnesses) == 0 {
		f.Verdict = Deferred
		f.Observed = "no witnesses to probe"
		return f
	}
	addr := s.env.Witnesses[0].addr
	resp, err := doPostBody(s.ctx, s.env.HTTP, "http://"+addr+"/daq/sign",
		"Bearer "+hex.EncodeToString([]byte("not-the-real-token!")), `{}`)
	if err != nil {
		f.Verdict = Fail
		f.Observed = "unexpected transport error"
		f.Evidence = err.Error()
		return f
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		f.Verdict = Fail
		f.Observed = fmt.Sprintf("HTTP %d (expected 401)", resp.StatusCode)
		f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
		return f
	}
	body, _ := readBody(resp)
	f.Verdict = Pass
	f.Observed = "HTTP 401 rejected without signing"
	f.Evidence = strings.TrimSpace(body)
	return f
}

// doPostBody is a tiny helper used by auth attacks.
func doPostBody(ctx context.Context, c *http.Client, url, auth, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return c.Do(req)
}

func readBody(resp *http.Response) (string, error) {
	var out strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return out.String(), nil
}
