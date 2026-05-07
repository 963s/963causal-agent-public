package siliconcert

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/963causal/agent/internal/daq"
)

func TestFromTicketVerifyAndJSON(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n := 5
	k := 3
	witnesses, rosterPubs, cleanup := startTestWitnesses(t, n)
	defer cleanup()

	entries := make([]daq.RosterEntry, n)
	for i, w := range witnesses {
		entries[i] = daq.RosterEntry{
			Index:  i,
			Label:  w.label,
			URL:    "http://" + w.addr,
			Pubkey: rosterPubs[i],
		}
	}

	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	req := buildTestRequest(agentPub, agentPriv, "silicon-cert-test")

	cfg := daq.ClientConfig{
		Roster:    entries,
		Threshold: k,
		Mode:      daq.ModeParallel,
		HTTP:      &http.Client{Timeout: 5 * time.Second},
	}

	ticket, err := daq.RequestQuorum(ctx, cfg, req)
	if err != nil {
		t.Fatalf("RequestQuorum: %v", err)
	}

	cert, err := FromTicket(ticket, "unit-test-workload")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(cert, rosterPubs); err != nil {
		t.Fatalf("Verify fresh cert: %v", err)
	}

	raw, err := cert.MarshalJSONBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(parsed, rosterPubs); err != nil {
		t.Fatalf("Verify after JSON round-trip: %v", err)
	}

	// Tamper must fail
	parsed.Ticket.AggSignature[0] ^= 1
	if err := Verify(parsed, rosterPubs); err == nil {
		t.Fatal("expected verify failure on tampered cert")
	}
}

type tw struct {
	index int
	label string
	addr  string
	srv   *http.Server
	ln    net.Listener
}

func startTestWitnesses(t *testing.T, n int) ([]*tw, []*daq.PublicKey, func()) {
	t.Helper()
	witnesses := make([]*tw, n)
	rosterPubs := make([]*daq.PublicKey, n)
	drandCli := daq.NewDrandClient(daq.DefaultDrandChain, nil)

	for i := 0; i < n; i++ {
		priv, pub, err := daq.GenerateKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		rosterPubs[i] = pub

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		lw := &tw{
			index: i,
			label: fmt.Sprintf("sc-test-w%d", i),
			addr:  ln.Addr().String(),
			ln:    ln,
		}
		handler := daq.WitnessHandler(daq.WitnessConfig{
			Index:       i,
			Label:       lw.label,
			Priv:        priv,
			Drand:       drandCli,
			MaxRoundLag: 4,
			VerifyDrand: false,
		})
		lw.srv = &http.Server{
			Handler:      handler,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			if err := lw.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				t.Logf("serve: %v", err)
			}
		}()
		witnesses[i] = lw
	}
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

func buildTestRequest(agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey, opID string) *daq.Request {
	payload := []byte("payload for " + opID)
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
		panic(err)
	}
	req.AgentSignature = ed25519.Sign(agentPriv, msg)
	return req
}

func TestSchemaConstant(t *testing.T) {
	if SchemaV1 != "963causal.silicon-cert/v1" {
		t.Fatal(SchemaV1)
	}
}
