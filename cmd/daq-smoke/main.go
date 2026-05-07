// daq-smoke spins up 5 in-process DAQ witnesses on loopback ports,
// runs both parallel and sequential quorum attestations through the
// full agent→witness→aggregate→verify pipeline, and exercises the
// three top failure paths (below-threshold, tampered sig, wrong
// op-hash). Exits non-zero on any regression.
//
// Goal: prove on this host, before any network deployment, that:
//
//   (a) 3 of 5 BDN signatures aggregate to a single 48-byte sig that
//       verifies under the BDN-aggregated public-key derivation;
//   (b) sequential-chain mode enforces ordering — witness i cannot
//       sign before witness i-1's signature is in hand;
//   (c) a tampered op-hash or a forged witness signature is caught
//       at the client before aggregation, and by the server-side
//       verifier afterwards.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/963causal/agent/internal/daq"
)

const (
	rosterSize = 5
	threshold  = 3
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- Stage 1: spin up 5 witnesses on loopback ----
	witnesses, rosterPubs, stop := startLocalWitnesses(ctx, rosterSize)
	defer stop()

	entries := make([]daq.RosterEntry, rosterSize)
	for i, w := range witnesses {
		entries[i] = daq.RosterEntry{
			Index:  i,
			Label:  w.label,
			URL:    "http://" + w.addr,
			Pubkey: rosterPubs[i],
		}
	}
	printRoster(entries)

	// ---- Stage 2: mint a fresh agent identity ----
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("agent keygen: %v", err)
	}
	log.Printf("agent pubkey=%x…", agentPub[:8])

	// ---- Stage 3: build a request anchored to local fake drand ----
	// We use a synthetic drand round so the smoke test does not need
	// internet access. The witness config has verify_drand=false in
	// this mode so everything runs offline.
	req := buildFakeRequest(agentPub, agentPriv, "op-happy-path")

	cfg := daq.ClientConfig{
		Roster:    entries,
		Threshold: threshold,
		Mode:      daq.ModeParallel,
		HTTP:      &http.Client{Timeout: 5 * time.Second},
	}

	// ---- Stage 4: PARALLEL HAPPY PATH ----
	log.Printf("\n=== parallel mode: expect 3-of-5 aggregate ticket ===")
	t0 := time.Now()
	ticket, err := daq.RequestQuorum(ctx, cfg, req)
	if err != nil {
		fatalf("parallel RequestQuorum: %v", err)
	}
	log.Printf("  ticket built in %v: mode=%s k=%d/n=%d agg_sig_bytes=%d mask=%x",
		time.Since(t0), ticket.Mode, ticket.Threshold, ticket.RosterSize,
		len(ticket.AggSignature), ticket.AggMask)
	logParticipants(rosterPubs, ticket.AggMask)

	if err := daq.VerifyTicket(ticket, rosterPubs); err != nil {
		fatalf("parallel VerifyTicket (happy): %v", err)
	}
	log.Printf("  verify: PASS")

	// ---- Stage 5: PARALLEL TAMPER PATH ----
	log.Printf("\n=== parallel mode: tampered aggregate signature must reject ===")
	bad := cloneTicket(ticket)
	bad.AggSignature[0] ^= 0x01
	if err := daq.VerifyTicket(bad, rosterPubs); err == nil {
		fatalf("tamper verify unexpectedly succeeded")
	} else {
		log.Printf("  verify: reject as expected: %v", err)
	}

	// ---- Stage 6: PARALLEL MASK FORGERY PATH ----
	log.Printf("\n=== parallel mode: forged mask (extra signer) must reject ===")
	forged := cloneTicket(ticket)
	forged.AggMask = append([]byte(nil), forged.AggMask...)
	// flip first unset bit ON
	for i := 0; i < rosterSize; i++ {
		if forged.AggMask[i/8]&(1<<uint(i%8)) == 0 {
			forged.AggMask[i/8] |= 1 << uint(i%8)
			break
		}
	}
	if err := daq.VerifyTicket(forged, rosterPubs); err == nil {
		fatalf("forged-mask verify unexpectedly succeeded")
	} else {
		log.Printf("  verify: reject as expected: %v", err)
	}

	// ---- Stage 7: BELOW-THRESHOLD PATH ----
	log.Printf("\n=== parallel mode: k=3 required, only 2 witnesses reachable ===")
	shortCfg := cfg
	// Make 3 witnesses "unreachable" by pointing them at a closed port.
	entriesSabotaged := make([]daq.RosterEntry, rosterSize)
	copy(entriesSabotaged, entries)
	for i := 2; i < rosterSize; i++ {
		entriesSabotaged[i].URL = "http://127.0.0.1:1" // nothing listens
	}
	shortCfg.Roster = entriesSabotaged
	if _, err := daq.RequestQuorum(ctx, shortCfg, req); err == nil {
		fatalf("below-threshold RequestQuorum unexpectedly succeeded")
	} else {
		log.Printf("  RequestQuorum: reject as expected: %v", err)
	}

	// ---- Stage 8: SEQUENTIAL CHAIN HAPPY PATH ----
	log.Printf("\n=== sequential mode: witness_i signs over (req || prev_sig) ===")
	seqReq := buildFakeRequest(agentPub, agentPriv, "op-sequential-chain")
	seqCfg := cfg
	seqCfg.Mode = daq.ModeSequential
	t0 = time.Now()
	seqTicket, err := daq.RequestQuorum(ctx, seqCfg, seqReq)
	if err != nil {
		fatalf("sequential RequestQuorum: %v", err)
	}
	log.Printf("  chain length %d built in %v", len(seqTicket.Witnesses), time.Since(t0))
	for i, ws := range seqTicket.Witnesses {
		log.Printf("    seq[%d] witness_index=%d sig=%x…",
			i, ws.WitnessIndex, ws.Signature[:6])
	}
	if err := daq.VerifyTicket(seqTicket, rosterPubs); err != nil {
		fatalf("sequential VerifyTicket (happy): %v", err)
	}
	log.Printf("  verify: PASS")

	// ---- Stage 9: SEQUENTIAL CHAIN REORDER PATH ----
	log.Printf("\n=== sequential mode: reorder witnesses must reject ===")
	reordered := cloneTicket(seqTicket)
	if len(reordered.Witnesses) >= 2 {
		reordered.Witnesses[0], reordered.Witnesses[1] = reordered.Witnesses[1], reordered.Witnesses[0]
	}
	if err := daq.VerifyTicket(reordered, rosterPubs); err == nil {
		fatalf("reordered-chain verify unexpectedly succeeded")
	} else {
		log.Printf("  verify: reject as expected: %v", err)
	}

	// ---- Stage 10: OPERATION-HASH TAMPER PATH ----
	log.Printf("\n=== post-hoc op_hash tamper must reject ===")
	opTamper := cloneTicket(ticket)
	opTamper.Request.OpHash = daq.HashOperationPayload([]byte("different payload"))
	if err := daq.VerifyTicket(opTamper, rosterPubs); err == nil {
		fatalf("op-hash tamper verify unexpectedly succeeded")
	} else {
		log.Printf("  verify: reject as expected: %v", err)
	}

	// ---- Result ----
	log.Printf("\n=== daq-smoke: all positive and negative paths PASS ===")
}

type localWitness struct {
	index int
	label string
	addr  string
	srv   *http.Server
	ln    net.Listener
}

// startLocalWitnesses brings up `n` in-process witnesses on loopback
// on ephemeral ports. Each gets its own BLS key and is wired to a
// drand client whose verify flag is OFF — we feed a fake drand round
// into every request so the smoke test runs offline. Returns the
// witness descriptors, their aggregated public keys (ordered by
// roster index), and a cleanup func.
func startLocalWitnesses(ctx context.Context, n int) ([]*localWitness, []*daq.PublicKey, func()) {
	witnesses := make([]*localWitness, n)
	rosterPubs := make([]*daq.PublicKey, n)
	drandCli := daq.NewDrandClient(daq.DefaultDrandChain, nil) // unused because verify=false

	for i := 0; i < n; i++ {
		priv, pub, err := daq.GenerateKeyPair()
		if err != nil {
			log.Fatalf("keygen[%d]: %v", i, err)
		}
		rosterPubs[i] = pub

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("listen[%d]: %v", i, err)
		}
		lw := &localWitness{
			index: i,
			label: fmt.Sprintf("local-w%d", i+1),
			addr:  ln.Addr().String(),
			ln:    ln,
		}
		handler := daq.WitnessHandler(daq.WitnessConfig{
			Index:       i,
			Label:       lw.label,
			Priv:        priv,
			Drand:       drandCli,
			MaxRoundLag: 4,
			VerifyDrand: false, // offline smoke test
		})
		lw.srv = &http.Server{
			Handler:      handler,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			if err := lw.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[w=%d] serve: %v", lw.index, err)
			}
		}()
		witnesses[i] = lw
	}
	// Give each socket a tick to start accepting.
	time.Sleep(50 * time.Millisecond)

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, w := range witnesses {
			_ = w.srv.Shutdown(shutdownCtx)
		}
	}
	return witnesses, rosterPubs, cleanup
}

// buildFakeRequest assembles a Request with a synthetic drand round
// so the smoke test runs without internet. The signature values are
// random bytes of the right length; witness-side verification of
// drand is disabled in the local harness.
func buildFakeRequest(agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey, opID string) *daq.Request {
	payload := []byte("operation payload for " + opID)
	drandSig := make([]byte, 48)
	_, _ = rand.Read(drandSig)
	req := &daq.Request{
		OpID:           opID,
		OpHash:         daq.HashOperationPayload(payload),
		AgentPubkey:    append([]byte(nil), agentPub...),
		DrandChain:     daq.DefaultDrandChain,
		DrandRound:     1234567,
		DrandSignature: drandSig,
		RequestedAtMs:  time.Now().UnixMilli(),
	}
	msg, err := daq.CanonicalRequestBytes(req)
	if err != nil {
		log.Fatalf("canonicalise: %v", err)
	}
	req.AgentSignature = ed25519.Sign(agentPriv, msg)
	return req
}

func cloneTicket(t *daq.Ticket) *daq.Ticket {
	c := *t
	c.Witnesses = append([]daq.WitnessSignature(nil), t.Witnesses...)
	c.AggSignature = append([]byte(nil), t.AggSignature...)
	c.AggMask = append([]byte(nil), t.AggMask...)
	c.Request.OpHash = append([]byte(nil), t.Request.OpHash...)
	c.Request.AgentPubkey = append([]byte(nil), t.Request.AgentPubkey...)
	c.Request.AgentSignature = append([]byte(nil), t.Request.AgentSignature...)
	c.Request.DrandSignature = append([]byte(nil), t.Request.DrandSignature...)
	return &c
}

func printRoster(entries []daq.RosterEntry) {
	log.Printf("roster (n=%d, threshold=%d):", len(entries), threshold)
	for _, e := range entries {
		pub, _ := e.Pubkey.MarshalBinary()
		log.Printf("  w=%d %s %s pubkey=%s…", e.Index, e.Label, e.URL,
			hex.EncodeToString(pub)[:16])
	}
}

func logParticipants(roster []*daq.PublicKey, mask []byte) {
	participants, err := daq.Participants(roster, mask)
	if err != nil {
		log.Printf("  participants: (err) %v", err)
		return
	}
	log.Printf("  participants: %v", participants)
}

func fatalf(format string, args ...any) {
	log.Printf("FAIL: "+format, args...)
	os.Exit(1)
}
