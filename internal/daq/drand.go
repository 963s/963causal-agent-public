package daq

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultDrandChain is the League of Entropy fastnet chain hash (3-s
// period, unchained BLS sigs on G1). Shared with internal/probe so
// W3/EWL and DAQ talk to the same chain — a host that already has a
// W3 trust relationship with drand reuses that here.
const DefaultDrandChain = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

// DefaultDrandEndpoints lists the official relays. DAQ tries them in
// sequence. Disagreement between relays is treated as a witness-level
// alarm: if two relays return different signatures for the same round
// the witness refuses to sign.
var DefaultDrandEndpoints = []string{
	"https://api.drand.sh",
	"https://api2.drand.sh",
	"https://api3.drand.sh",
	"https://drand.cloudflare.com",
}

// Round is the parsed form of a drand public beacon entry. Only
// fields the DAQ protocol actually uses are kept.
type Round struct {
	Chain     string
	Round     uint64
	Randomness []byte // 32B
	Signature []byte // 48B (G1 compressed)
	// RoundTimeUnix is the POSIX second the round was SUPPOSED to be
	// drawn, computed from chain genesis + period. The witness checks
	// |now - RoundTimeUnix| to bound freshness.
	RoundTimeUnix int64
	Period        int // seconds between rounds
}

// ChainInfo captures the static drand chain metadata a witness needs
// to check freshness: period and genesis time. Cached by
// NewDrandClient the first time it talks to a chain.
type ChainInfo struct {
	Chain       string
	Period      int
	GenesisTime int64
	PublicKey   []byte // 96B G2 (carried for completeness; MVP does not BLS-verify drand)
}

// drandClient is a tiny HTTP client tuned for DAQ. It is deliberately
// NOT sharing the package-level http.DefaultClient because DAQ wants
// short timeouts and its own User-Agent — witnesses probe drand often.
type drandClient struct {
	endpoints []string
	http      *http.Client
	chain     string
	info      *ChainInfo
}

// NewDrandClient builds a client pinned to the supplied chain. Pass
// the empty string to take DefaultDrandChain. The constructor does
// not reach out to the network; the first FetchRound or Info call
// fetches and caches the chain info.
func NewDrandClient(chain string, endpoints []string) *drandClient {
	if chain == "" {
		chain = DefaultDrandChain
	}
	if len(endpoints) == 0 {
		endpoints = DefaultDrandEndpoints
	}
	return &drandClient{
		chain:     chain,
		endpoints: endpoints,
		http: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

// Chain returns the chain hash the client is pinned to.
func (c *drandClient) Chain() string { return c.chain }

// Info returns (and caches) the chain's period / genesis / public
// key. Callers usually do not need this — FetchRound / FetchLatest
// call it transparently — but the witness startup uses it to
// pre-warm the cache.
func (c *drandClient) Info(ctx context.Context) (*ChainInfo, error) {
	if c.info != nil {
		return c.info, nil
	}
	type respBody struct {
		Period      int    `json:"period"`
		GenesisTime int64  `json:"genesis_time"`
		PublicKey   string `json:"public_key"`
	}
	var lastErr error
	for _, ep := range c.endpoints {
		url := fmt.Sprintf("%s/%s/info", ep, c.chain)
		raw, err := c.getJSON(ctx, url)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", ep, err)
			continue
		}
		var r respBody
		if err := json.Unmarshal(raw, &r); err != nil {
			lastErr = fmt.Errorf("%s: unmarshal: %w", ep, err)
			continue
		}
		if r.Period <= 0 {
			lastErr = fmt.Errorf("%s: period=%d", ep, r.Period)
			continue
		}
		pk, _ := hex.DecodeString(r.PublicKey)
		c.info = &ChainInfo{
			Chain:       c.chain,
			Period:      r.Period,
			GenesisTime: r.GenesisTime,
			PublicKey:   pk,
		}
		return c.info, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("daq/drand: chain info: %w", lastErr)
	}
	return nil, errors.New("daq/drand: no reachable endpoint for chain info")
}

// FetchLatest returns the most recent round the chain has published.
// Used by the agent to anchor a request in freshness.
func (c *drandClient) FetchLatest(ctx context.Context) (*Round, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	return c.fetchPath(ctx, info, "latest")
}

// FetchRound fetches a specific round by number. Witnesses use this
// to cross-check that the round the agent supplied is indeed what
// drand served.
func (c *drandClient) FetchRound(ctx context.Context, round uint64) (*Round, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	return c.fetchPath(ctx, info, fmt.Sprintf("%d", round))
}

func (c *drandClient) fetchPath(ctx context.Context, info *ChainInfo, path string) (*Round, error) {
	type respBody struct {
		Round             uint64 `json:"round"`
		Randomness        string `json:"randomness"`
		Signature         string `json:"signature"`
	}
	var lastErr error
	for _, ep := range c.endpoints {
		url := fmt.Sprintf("%s/%s/public/%s", ep, c.chain, path)
		raw, err := c.getJSON(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		var r respBody
		if err := json.Unmarshal(raw, &r); err != nil {
			lastErr = err
			continue
		}
		if r.Round == 0 || r.Signature == "" {
			lastErr = errors.New("drand: empty round in response")
			continue
		}
		randBytes, err := hex.DecodeString(r.Randomness)
		if err != nil {
			lastErr = err
			continue
		}
		sigBytes, err := hex.DecodeString(r.Signature)
		if err != nil {
			lastErr = err
			continue
		}
		if len(sigBytes) != 48 {
			lastErr = fmt.Errorf("drand: sig size %d, expected 48", len(sigBytes))
			continue
		}
		return &Round{
			Chain:         c.chain,
			Round:         r.Round,
			Randomness:    randBytes,
			Signature:     sigBytes,
			Period:        info.Period,
			RoundTimeUnix: info.GenesisTime + int64(r.Round-1)*int64(info.Period),
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("daq/drand: no endpoint returned round")
	}
	return nil, lastErr
}

func (c *drandClient) getJSON(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "963causal-agent/daq")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drand: http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16*1024))
}

// ExpectedRound returns the round number drand SHOULD be on at `now`
// given the chain's genesis + period. Witnesses use this to detect
// a request carrying a round far in the past or future.
func ExpectedRound(info *ChainInfo, now time.Time) uint64 {
	if info == nil || info.Period <= 0 {
		return 0
	}
	dt := now.Unix() - info.GenesisTime
	if dt < 0 {
		return 1
	}
	return uint64(dt/int64(info.Period)) + 1
}

// CheckFreshness compares a round against the chain's expected round
// at `now` and fails if the gap exceeds `maxLag` rounds. MVP default:
// ±2 rounds = ±6 s of drift on fastnet, matching the witness accept
// window agreed in BSL §12 ADR-004.
func CheckFreshness(info *ChainInfo, round uint64, now time.Time, maxLag int) error {
	if info == nil {
		return errors.New("daq/drand: nil chain info")
	}
	expected := ExpectedRound(info, now)
	var gap int64
	switch {
	case round > expected:
		gap = int64(round - expected)
	default:
		gap = int64(expected - round)
	}
	if gap > int64(maxLag) {
		return fmt.Errorf("daq/drand: round %d lags expected %d by %d rounds (> %d)",
			round, expected, gap, maxLag)
	}
	return nil
}
