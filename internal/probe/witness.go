// Package probe — External Witness.
//
// The External Witness probe fetches a freshly-published public
// randomness value from the drand League of Entropy beacon chain and
// embeds the round number, value, and BLS threshold signature inside
// the frame.
//
// Why this replaces the "Cosmic Witness / CMB antenna" idea:
//
//   * CMB requires cryogenic cooling (sub-100 mK) and is a PUBLIC signal
//     that any attacker in the same hemisphere can also receive — so it
//     is not a shared-secret source, only a shared-clock source.
//   * What we actually need from CMB is the property "no adversary could
//     have predicted this value 30 seconds ago". drand provides exactly
//     that property, cryptographically, with zero hardware cost:
//
//       - drand produces a new 32-byte randomness value every 30 s.
//       - Each round is signed by ≥ t-of-n BLS12-381 threshold operators
//         (15+ independent organizations: Cloudflare, EPFL, Kudelski,
//         PQ Shield, Protocol Labs, ...). Forging requires compromising
//         all t of them simultaneously.
//       - The randomness for round R is genuinely unpredictable before
//         round R's drawing; after R it is publicly verifiable forever.
//
// Security property delivered:
//
//   An attacker who captures an agent's Ed25519 private key and its
//   encrypted payload cannot fabricate a "fresh-looking" frame offline,
//   because every frame must carry a beacon round whose signature can
//   only be known AFTER that round was drawn in real time. The server
//   enforces |captured_at - round_time| < 45 s (1.5× round period) and
//   refuses frames whose beacon round is too old or in the future.
//
// Endpoint: https://api.drand.sh  (mainnet, League of Entropy).
// Docs: https://drand.love/docs/
package probe

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	agentpb "github.com/963causal/agent/proto"
)

// DefaultDrandChain is the League of Entropy mainnet "fastnet" chain:
// 3-second period, BLS12-381 on G1, unchained randomness. The chain
// hash is embedded in the frame so the server knows which public key
// set to verify against.
const DefaultDrandChain = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

// defaultWitnessEndpoints lists several drand relays; we try them in
// order. Using multiple independent relays makes it possible to detect
// a rogue local DNS/proxy serving a stale beacon round.
var defaultWitnessEndpoints = []string{
	"https://api.drand.sh",
	"https://api2.drand.sh",
	"https://api3.drand.sh",
	"https://drand.cloudflare.com",
}

// WitnessConfig controls the beacon fetch.
type WitnessConfig struct {
	ChainHash string
	Endpoints []string
	Timeout   time.Duration
}

func defaultWitness() WitnessConfig {
	return WitnessConfig{
		ChainHash: DefaultDrandChain,
		Endpoints: defaultWitnessEndpoints,
		Timeout:   3 * time.Second,
	}
}

// SampleExternalWitness fetches the latest drand round and returns it
// packed as an ExternalWitness message. Returns nil (not error) if all
// relays fail — the probe is best-effort so a temporarily offline host
// still ships frames; the server simply records "witness missing" as a
// minor trust penalty.
func SampleExternalWitness(ctx context.Context, cfgOpt ...WitnessConfig) *agentpb.ExternalWitness {
	cfg := defaultWitness()
	if len(cfgOpt) > 0 {
		c := cfgOpt[0]
		if c.ChainHash != "" {
			cfg.ChainHash = c.ChainHash
		}
		if len(c.Endpoints) > 0 {
			cfg.Endpoints = c.Endpoints
		}
		if c.Timeout > 0 {
			cfg.Timeout = c.Timeout
		}
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	for _, ep := range cfg.Endpoints {
		resp, err := fetchLatest(ctx, ep, cfg.ChainHash)
		if err != nil {
			continue
		}
		return resp
	}
	return nil
}

type drandResponse struct {
	Round             uint64 `json:"round"`
	Randomness        string `json:"randomness"`
	Signature         string `json:"signature"`
	PreviousSignature string `json:"previous_signature"`
}

type drandInfo struct {
	Period      int   `json:"period"`
	GenesisTime int64 `json:"genesis_time"`
}

func fetchLatest(ctx context.Context, endpoint, chainHash string) (*agentpb.ExternalWitness, error) {
	// /public/latest returns the most recent drawn round.
	url := fmt.Sprintf("%s/%s/public/latest", endpoint, chainHash)
	body, err := httpGetJSON(ctx, url)
	if err != nil {
		return nil, err
	}
	var r drandResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if r.Round == 0 || r.Randomness == "" || r.Signature == "" {
		return nil, errors.New("drand: empty response")
	}

	randBytes, err := hex.DecodeString(r.Randomness)
	if err != nil {
		return nil, fmt.Errorf("drand: bad randomness hex: %w", err)
	}
	sigBytes, err := hex.DecodeString(r.Signature)
	if err != nil {
		return nil, fmt.Errorf("drand: bad signature hex: %w", err)
	}

	// Derive the round time from chain metadata so the server can enforce
	// freshness without trusting the agent's clock.
	info, err := fetchInfo(ctx, endpoint, chainHash)
	var roundTime int64
	if err == nil && info.Period > 0 {
		roundTime = info.GenesisTime + int64(r.Round-1)*int64(info.Period)
	}

	return &agentpb.ExternalWitness{
		ChainHash:     chainHash,
		Round:         r.Round,
		Randomness:    randBytes,
		Signature:     sigBytes,
		CapturedAtMs:  time.Now().UnixMilli(),
		RoundTimeUnix: roundTime,
	}, nil
}

func fetchInfo(ctx context.Context, endpoint, chainHash string) (*drandInfo, error) {
	url := fmt.Sprintf("%s/%s/info", endpoint, chainHash)
	body, err := httpGetJSON(ctx, url)
	if err != nil {
		return nil, err
	}
	var info drandInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

var witnessClient = &http.Client{
	Timeout: 3 * time.Second,
}

func httpGetJSON(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "963causal-agent/witness")
	resp, err := witnessClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16*1024))
}
