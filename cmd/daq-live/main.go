// daq-live runs an end-to-end DAQ attestation against 5 real
// 963causal-witness processes (spawned via go os/exec) with drand
// verification turned ON. Unlike daq-smoke it requires internet
// access because every witness independently contacts drand to
// cross-check the round the agent anchored against.
//
// Success criteria: 3-of-5 aggregate quorum built + verified when
// drand is live; witness rejects when we tamper with the drand
// signature in the request.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/963causal/agent/internal/daq"
)

const (
	rosterSize = 5
	threshold  = 3
)

func main() {
	binPath := os.Getenv("WITNESS_BIN")
	if binPath == "" {
		binPath = "/home/ubuntu/963causal-agent/bin/963causal-witness"
	}
	if _, err := os.Stat(binPath); err != nil {
		log.Fatalf("witness binary missing at %s: %v", binPath, err)
	}

	keyDir, err := os.MkdirTemp("", "daq-live-keys-")
	if err != nil {
		log.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(keyDir)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// ---- Pick 5 free loopback ports ----
	ports := make([]int, rosterSize)
	for i := range ports {
		ports[i] = freePort()
	}

	// ---- Spawn 5 witness processes ----
	procs := make([]*exec.Cmd, rosterSize)
	for i := 0; i < rosterSize; i++ {
		keyPath := filepath.Join(keyDir, fmt.Sprintf("w%d.key", i))
		addr := fmt.Sprintf("127.0.0.1:%d", ports[i])
		cmd := exec.CommandContext(ctx, binPath,
			"--addr", addr,
			"--key", keyPath,
			"--index", fmt.Sprintf("%d", i),
			"--label", fmt.Sprintf("live-w%d", i+1),
			"--verify-drand=true",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			log.Fatalf("spawn w=%d: %v", i, err)
		}
		procs[i] = cmd
	}
	defer func() {
		for _, p := range procs {
			_ = p.Process.Signal(os.Interrupt)
		}
		time.Sleep(300 * time.Millisecond)
	}()

	// Wait for every witness to respond on /daq/info.
	httpc := &http.Client{Timeout: 3 * time.Second}
	rosterPubs := make([]*daq.PublicKey, rosterSize)
	entries := make([]daq.RosterEntry, rosterSize)
	for i := 0; i < rosterSize; i++ {
		url := fmt.Sprintf("http://127.0.0.1:%d", ports[i])
		info, err := waitInfo(ctx, httpc, url, 20*time.Second)
		if err != nil {
			log.Fatalf("w=%d info: %v", i, err)
		}
		pub, err := daq.UnmarshalPublicKey(info.PubkeyBytes)
		if err != nil {
			log.Fatalf("w=%d unmarshal pub: %v", i, err)
		}
		rosterPubs[i] = pub
		entries[i] = daq.RosterEntry{
			Index:  i,
			Label:  info.Label,
			URL:    url,
			Pubkey: pub,
		}
	}
	log.Printf("5 witnesses live, drand chain=%s", daq.DefaultDrandChain)

	// ---- Agent identity ----
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("agent keygen: %v", err)
	}

	drandCli := daq.NewDrandClient(daq.DefaultDrandChain, nil)

	// ---- Build + submit PARALLEL request (drand verified by witnesses) ----
	op := daq.Operation{ID: "live-parallel", Payload: []byte("live happy path")}
	req, err := daq.BuildRequest(ctx, drandCli, agentPub, agentPriv, op)
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	log.Printf("request anchored to drand round=%d", req.DrandRound)

	cfg := daq.ClientConfig{
		Roster:    entries,
		Threshold: threshold,
		Mode:      daq.ModeParallel,
		HTTP:      &http.Client{Timeout: 10 * time.Second},
		Drand:     drandCli,
	}
	t0 := time.Now()
	ticket, err := daq.RequestQuorum(ctx, cfg, req)
	if err != nil {
		log.Fatalf("quorum: %v", err)
	}
	log.Printf("parallel quorum built in %v (mask=%x)", time.Since(t0), ticket.AggMask)
	if err := daq.VerifyTicket(ticket, rosterPubs); err != nil {
		log.Fatalf("verify: %v", err)
	}
	log.Printf("verify PASS")

	// ---- Tamper the drand signature in the request; witness must reject ----
	log.Printf("\n=== tamper drand sig: witnesses should reject ===")
	badReq := *req
	badReq.DrandSignature = append([]byte(nil), req.DrandSignature...)
	badReq.DrandSignature[0] ^= 0x01
	// Re-sign the agent bytes because drand_sig is part of the signed
	// envelope; otherwise the witness rejects for a different reason.
	msg, _ := daq.CanonicalRequestBytes(&badReq)
	badReq.AgentSignature = ed25519.Sign(agentPriv, msg)
	if _, err := daq.RequestQuorum(ctx, cfg, &badReq); err == nil {
		log.Fatalf("drand-tamper quorum unexpectedly succeeded")
	} else {
		log.Printf("reject as expected: %v", err)
	}

	// ---- Sequential over real drand ----
	log.Printf("\n=== sequential mode with live drand ===")
	seqReq, err := daq.BuildRequest(ctx, drandCli, agentPub, agentPriv,
		daq.Operation{ID: "live-seq", Payload: []byte("live sequential")})
	if err != nil {
		log.Fatalf("build seq request: %v", err)
	}
	seqCfg := cfg
	seqCfg.Mode = daq.ModeSequential
	t0 = time.Now()
	seqTicket, err := daq.RequestQuorum(ctx, seqCfg, seqReq)
	if err != nil {
		log.Fatalf("seq quorum: %v", err)
	}
	log.Printf("sequential quorum built in %v (%d witnesses)",
		time.Since(t0), len(seqTicket.Witnesses))
	if err := daq.VerifyTicket(seqTicket, rosterPubs); err != nil {
		log.Fatalf("seq verify: %v", err)
	}
	log.Printf("verify PASS")

	log.Printf("\n=== daq-live: all paths PASS ===")
}

type infoReply struct {
	Label       string
	PubkeyBytes []byte
}

func waitInfo(ctx context.Context, hc *http.Client, url string, budget time.Duration) (*infoReply, error) {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/daq/info", nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(r)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			var raw struct {
				Label  string `json:"label"`
				Pubkey string `json:"pubkey"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				return nil, err
			}
			pub, err := decodeHex(raw.Pubkey)
			if err != nil {
				return nil, err
			}
			return &infoReply{Label: raw.Label, PubkeyBytes: pub}, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("witness did not come up within %v", budget)
}

func decodeHex(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	_, err := fmt.Sscanf(s, "%x", &b)
	return b, err
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	return addr.Port
}
