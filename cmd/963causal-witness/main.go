// Command 963causal-witness is a single DAQ witness. It loads (or mints)
// a BDN private key from disk, fetches drand chain metadata once at
// startup, and serves:
//
//   GET  /daq/info     — returns {witness_index, label, pubkey,
//                                  drand_chain}; used by the agent to
//                                  bootstrap its roster.
//   POST /daq/sign     — the signing endpoint. Accepts the JSON body
//                        defined in internal/daq/witness.go, validates
//                        the agent's Ed25519 signature, optionally
//                        cross-checks drand, and returns a BDN
//                        signature over the canonical witness input.
//
// A production deployment runs five of these on distinct ports (or
// hosts); a local smoke test spins up five in-process. Either way the
// roster of (index, url, pubkey) must be the same on both sides.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/963causal/agent/internal/daq"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:17001", "HTTP listen address")
	keyPath := flag.String("key", "", "path to persist the BLS key (empty = in-memory only)")
	idx := flag.Int("index", 0, "roster index for this witness (0..n-1)")
	label := flag.String("label", "witness", "human-readable label")
	chain := flag.String("drand-chain", daq.DefaultDrandChain, "drand chain hash")
	verifyDrand := flag.Bool("verify-drand", true, "BLS-verify drand beacon against pinned chain pubkey + freshness")
	maxLag := flag.Int("max-round-lag", 4, "max |expected-round - supplied-round| before rejecting")
	authTokenFlag := flag.String("auth-token", "", "required bearer token on /daq/sign; reads CAUSAL_963_WITNESS_AUTH_TOKEN if flag empty")
	authTokenFile := flag.String("auth-token-file", "", "read the bearer token from this path (overrides --auth-token / env)")
	chainPubkeyHex := flag.String("chain-pubkey", daq.WellKnownFastnetChainPubkey, "96-byte hex G2 pubkey for the drand chain (default: LoE fastnet)")
	flag.Parse()

	priv, pub, minted, err := daq.LoadOrCreateWitnessKey(*keyPath)
	if err != nil {
		log.Fatalf("witness: key: %v", err)
	}
	pubBytes, _ := pub.MarshalBinary()
	log.Printf("witness w=%d label=%q listen=%s pubkey=%x… drand=%s (minted=%v)",
		*idx, *label, *addr, pubBytes[:8], *chain, minted)

	drandCli := daq.NewDrandClient(*chain, nil)
	if *verifyDrand {
		// Pre-warm the chain info so the first /daq/sign call isn't
		// blocked on discovery.
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		_, err := drandCli.Info(ctx)
		cancel()
		if err != nil {
			log.Printf("witness: drand chain info unreachable at startup (%v); will keep trying per-request", err)
		}
	}

	// Resolve auth token, in priority order:
	//   1. --auth-token-file     (preferred for systemd: permissions 0400 root-owned)
	//   2. --auth-token          (convenient for CLI bring-up)
	//   3. CAUSAL_963_WITNESS_AUTH_TOKEN env var (convenient for compose/k8s)
	// An empty final value keeps the pre-W7 no-auth behaviour so
	// existing smoke tests still work; production deployments
	// (systemd unit shipped alongside this binary) always set one.
	authToken := *authTokenFlag
	if *authTokenFile != "" {
		raw, err := os.ReadFile(*authTokenFile)
		if err != nil {
			log.Fatalf("witness: read auth token file %q: %v", *authTokenFile, err)
		}
		authToken = strings.TrimSpace(string(raw))
	} else if authToken == "" {
		authToken = strings.TrimSpace(os.Getenv("CAUSAL_963_WITNESS_AUTH_TOKEN"))
	}
	var authTokenHash []byte
	if authToken != "" {
		authTokenHash = daq.HashAuthToken(authToken)
		log.Printf("witness: bearer-token auth ENABLED (hash=%x…)", authTokenHash[:4])
	} else {
		log.Printf("witness: bearer-token auth DISABLED — accepting unauthenticated /daq/sign")
	}

	pinnedPub, err := decodePinnedChainPubkey(*chainPubkeyHex)
	if err != nil {
		log.Fatalf("witness: --chain-pubkey: %v", err)
	}

	handler := daq.WitnessHandler(daq.WitnessConfig{
		Index:            *idx,
		Label:            *label,
		Priv:             priv,
		Drand:            drandCli,
		MaxRoundLag:      *maxLag,
		VerifyDrand:      *verifyDrand,
		DrandChainPubkey: pinnedPub,
		AuthTokenHash:    authTokenHash,
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("witness: listen %s: %v", *addr, err)
	}
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	log.Printf("witness ready on http://%s", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("witness: serve: %v", err)
	}
	_ = fmt.Sprintf
}

// decodePinnedChainPubkey converts the --chain-pubkey flag value to
// raw bytes, accepting either the LoE-fastnet hex constant or a
// custom 96-byte G2 point. An explicit empty string re-enables the
// library default.
func decodePinnedChainPubkey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return daq.ExpectedChainPubkey(), nil
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	if len(raw) != 96 {
		return nil, fmt.Errorf("must be 96 bytes, got %d", len(raw))
	}
	return raw, nil
}
