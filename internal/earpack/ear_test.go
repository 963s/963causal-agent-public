package earpack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/963causal/agent/internal/daq"
	"github.com/963causal/agent/internal/siliconcert"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"ear"}`)
	kid := ExportKID(priv.Public().(ed25519.PublicKey))
	out, err := SignCOSE1Sign1(payload, priv, kid, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCOSE1Sign1(out, priv.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestFullPipelineSiliconcertToEAR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n := 5
	k := 3
	witnesses, rosterPubs, cleanup := startWitnesses(t, n)
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
	req := buildDAQReq(agentPub, agentPriv, "ear-pipeline-test")

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

	cert, err := siliconcert.FromTicket(ticket, "integration-ear")
	if err != nil {
		t.Fatal(err)
	}
	if err := siliconcert.Verify(cert, rosterPubs); err != nil {
		t.Fatal(err)
	}

	_, expPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coseBin, err := SignDocument(cert, expPriv, "test-scope")
	if err != nil {
		t.Fatal(err)
	}

	p, cert2, err := VerifyDocument(coseBin, expPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if p.V != EARVersion {
		t.Fatalf("version %s", p.V)
	}
	if err := siliconcert.Verify(cert2, rosterPubs); err != nil {
		t.Fatalf("inner cert verify: %v", err)
	}
	if cert2.Workload.OpID != cert.Workload.OpID {
		t.Fatal("round-trip mismatch")
	}
	t.Logf("EAR COSE size=%d kid=%s", len(coseBin), hex.EncodeToString(ExportKID(expPriv.Public().(ed25519.PublicKey))))
}

type lw struct {
	index int
	label string
	addr  string
	srv   *http.Server
	ln    net.Listener
}

func startWitnesses(t *testing.T, n int) ([]*lw, []*daq.PublicKey, func()) {
	t.Helper()
	witnesses := make([]*lw, n)
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
		w := &lw{
			index: i,
			label: fmt.Sprintf("ear-w%d", i),
			addr:  ln.Addr().String(),
			ln:    ln,
		}
		handler := daq.WitnessHandler(daq.WitnessConfig{
			Index:       i,
			Label:       w.label,
			Priv:        priv,
			Drand:       drandCli,
			MaxRoundLag: 4,
			VerifyDrand: false,
		})
		w.srv = &http.Server{
			Handler:      handler,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			if err := w.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				t.Logf("serve: %v", err)
			}
		}()
		witnesses[i] = w
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

func buildDAQReq(agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey, opID string) *daq.Request {
	payload := []byte("payload for " + opID)
	drandSig := make([]byte, 48)
	_, _ = rand.Read(drandSig)
	req := &daq.Request{
		OpID:           opID,
		OpHash:         daq.HashOperationPayload(payload),
		AgentPubkey:    append([]byte(nil), agentPub...),
		DrandChain:     daq.DefaultDrandChain,
		DrandRound:     7654321,
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
