package daq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// RosterEntry describes one witness as seen by the agent: the HTTP
// URL where it serves /daq/sign plus the BDN public key the agent
// should expect in the response. The index field is the position in
// the roster that feeds the BDN mask; it MUST be stable across runs
// and match what each witness claims on /daq/info.
//
// AuthToken is the plaintext bearer token the client attaches on
// every /daq/sign call; empty means "the witness runs in no-auth
// mode". In production (W7+) every witness MUST require a token so
// internet scanners cannot probe the signer.
type RosterEntry struct {
	Index     int
	Label     string
	URL       string
	Pubkey    *PublicKey
	AuthToken string
}

// ClientConfig bundles everything the agent-side DAQ coordinator
// needs to run one attestation round.
type ClientConfig struct {
	// Roster is the ordered list of all enrolled witnesses. Quorum
	// aggregation is meaningful only if every DAQ participant shares
	// the same view of this list.
	Roster []RosterEntry
	// Threshold is k — the minimum number of witness signatures
	// required to consider the quorum valid. Server-side verifiers
	// enforce the same value; misconfiguration fails closed.
	Threshold int
	// Mode picks parallel aggregate-BLS or the TCL-v2-inspired
	// sequential chain.
	Mode Mode
	// Drand lets the agent anchor the request freshness. If nil, a
	// default client is constructed against the League of Entropy.
	Drand *drandClient
	// HTTP is the client used to reach each witness; callers can
	// inject a short-timeout or test client.
	HTTP *http.Client
}

// withDefaults normalises a ClientConfig before use. Zero values for
// Threshold are rejected because "0-of-N" would silently produce
// tickets any attacker could forge.
func (c *ClientConfig) withDefaults() (ClientConfig, error) {
	out := *c
	if len(out.Roster) == 0 {
		return out, errors.New("daq/client: empty roster")
	}
	if out.Threshold < 1 {
		return out, errors.New("daq/client: threshold must be ≥ 1")
	}
	if out.Threshold > len(out.Roster) {
		return out, fmt.Errorf("daq/client: threshold %d > roster size %d",
			out.Threshold, len(out.Roster))
	}
	if out.Mode != ModeParallel && out.Mode != ModeSequential {
		return out, fmt.Errorf("daq/client: unknown mode %v", out.Mode)
	}
	if out.HTTP == nil {
		out.HTTP = &http.Client{Timeout: 8 * time.Second}
	}
	if out.Drand == nil {
		out.Drand = NewDrandClient("", nil)
	}
	// Roster must be indexed 0..n-1 with no gaps; a stray or
	// duplicated index silently breaks the BDN mask.
	indexSeen := make(map[int]bool, len(out.Roster))
	for _, e := range out.Roster {
		if e.Index < 0 || e.Index >= len(out.Roster) {
			return out, fmt.Errorf("daq/client: roster index %d out of range", e.Index)
		}
		if indexSeen[e.Index] {
			return out, fmt.Errorf("daq/client: duplicate roster index %d", e.Index)
		}
		if e.Pubkey == nil {
			return out, fmt.Errorf("daq/client: roster[%d] has nil pubkey", e.Index)
		}
		indexSeen[e.Index] = true
	}
	return out, nil
}

// Operation describes the sensitive action the agent wants to gate
// behind DAQ consensus. OpID is any opaque string (UUID, URI, etc.);
// Payload is the raw bytes whose hash is locked into the ticket.
type Operation struct {
	ID      string
	Payload []byte
}

// BuildRequest runs the agent-side pre-flight: fetch a fresh drand
// round, hash the operation payload, and sign the canonical bytes
// with the supplied Ed25519 private key (typically the W5b PUF-
// derived identity). Returns a Request ready to hand to RequestQuorum.
func BuildRequest(ctx context.Context, drand *drandClient, agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey, op Operation) (*Request, error) {
	if drand == nil {
		return nil, errors.New("daq/client: nil drand")
	}
	if len(agentPub) != ed25519.PublicKeySize || len(agentPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("daq/client: bad agent keypair sizes")
	}
	round, err := drand.FetchLatest(ctx)
	if err != nil {
		return nil, fmt.Errorf("daq/client: fetch latest drand: %w", err)
	}
	req := &Request{
		OpID:           op.ID,
		OpHash:         HashOperationPayload(op.Payload),
		AgentPubkey:    append([]byte(nil), agentPub...),
		DrandChain:     round.Chain,
		DrandRound:     round.Round,
		DrandSignature: round.Signature,
		RequestedAtMs:  time.Now().UnixMilli(),
	}
	msg, err := CanonicalRequestBytes(req)
	if err != nil {
		return nil, err
	}
	req.AgentSignature = ed25519.Sign(agentPriv, msg)
	return req, nil
}

// RequestQuorum drives the full k-of-n attestation. In ParallelMode
// the witnesses are contacted concurrently and the first `k`
// successful replies are aggregated; in SequentialMode the client
// walks the roster in index order, feeding each witness the previous
// witness's signature so that witness_i cannot sign before
// witness_{i-1} responds.
//
// Returns a Ticket on success. On failure (network, witness veto,
// below-threshold) returns an error that enumerates the reason from
// each witness for operator-side triage.
func RequestQuorum(ctx context.Context, raw ClientConfig, req *Request) (*Ticket, error) {
	cfg, err := raw.withDefaults()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("daq/client: nil request")
	}
	switch cfg.Mode {
	case ModeParallel:
		return requestParallel(ctx, cfg, req)
	case ModeSequential:
		return requestSequential(ctx, cfg, req)
	default:
		return nil, fmt.Errorf("daq/client: unhandled mode %v", cfg.Mode)
	}
}

type collectedSig struct {
	roster RosterEntry
	sig    []byte
	err    error
}

func requestParallel(ctx context.Context, cfg ClientConfig, req *Request) (*Ticket, error) {
	roster := sortedRoster(cfg.Roster)
	results := make(chan collectedSig, len(roster))
	var wg sync.WaitGroup
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, entry := range roster {
		entry := entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			input, err := WitnessInput(req, ModeParallel, 0, nil)
			if err != nil {
				results <- collectedSig{roster: entry, err: err}
				return
			}
			sig, err := postWitness(subCtx, cfg.HTTP, entry, req, ModeParallel, 0, nil)
			if err != nil {
				results <- collectedSig{roster: entry, err: err}
				return
			}
			// Cheap sanity check: a witness that returns a valid-size
			// signature that does NOT verify on the expected input is
			// either buggy or malicious; drop it before it poisons the
			// aggregate.
			if err := VerifyIndividual(entry.Pubkey, input, sig); err != nil {
				results <- collectedSig{
					roster: entry,
					err:    fmt.Errorf("individual verify: %w", err),
				}
				return
			}
			results <- collectedSig{roster: entry, sig: sig}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	rosterPubs := make([]*PublicKey, len(roster))
	for _, e := range roster {
		rosterPubs[e.Index] = e.Pubkey
	}

	var good []collectedSig
	var failures []string
	for rc := range results {
		if rc.err != nil {
			failures = append(failures,
				fmt.Sprintf("[w=%d %s] %v", rc.roster.Index, rc.roster.Label, rc.err))
			continue
		}
		good = append(good, rc)
		if len(good) >= cfg.Threshold {
			// Stop polling the rest; the context cancel propagates.
			cancel()
		}
	}
	if len(good) < cfg.Threshold {
		return nil, fmt.Errorf("daq/client: only %d of required %d witnesses signed; failures: %s",
			len(good), cfg.Threshold, joinReasons(failures))
	}

	// Sort participants by roster index so the bitmask aligns.
	sort.Slice(good, func(i, j int) bool { return good[i].roster.Index < good[j].roster.Index })
	participants := make([]int, cfg.Threshold)
	sigs := make([][]byte, cfg.Threshold)
	witnesses := make([]WitnessSignature, cfg.Threshold)
	for i := 0; i < cfg.Threshold; i++ {
		participants[i] = good[i].roster.Index
		sigs[i] = good[i].sig
		pub, _ := good[i].roster.Pubkey.MarshalBinary()
		witnesses[i] = WitnessSignature{
			WitnessIndex: good[i].roster.Index,
			Pubkey:       pub,
			Signature:    good[i].sig,
		}
	}
	agg, err := AggregateSigs(rosterPubs, participants, sigs)
	if err != nil {
		return nil, fmt.Errorf("daq/client: aggregate: %w", err)
	}
	return &Ticket{
		Request:      *req,
		Mode:         ModeParallel,
		Threshold:    cfg.Threshold,
		RosterSize:   len(roster),
		Witnesses:    witnesses,
		AggSignature: agg.Signature,
		AggMask:      agg.Mask,
		CreatedAtMs:  time.Now().UnixMilli(),
	}, nil
}

func requestSequential(ctx context.Context, cfg ClientConfig, req *Request) (*Ticket, error) {
	roster := sortedRoster(cfg.Roster)
	var (
		prevSig []byte
		chain   []WitnessSignature
		errs    []string
	)
	for seqIdx, entry := range roster {
		// Each hop gets its own short budget so a single flaky
		// witness cannot tie up the whole request for minutes.
		stepCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		sig, err := postWitness(stepCtx, cfg.HTTP, entry, req, ModeSequential, seqIdx, prevSig)
		cancel()
		if err != nil {
			errs = append(errs,
				fmt.Sprintf("[seq=%d w=%d %s] %v", seqIdx, entry.Index, entry.Label, err))
			if len(chain) >= cfg.Threshold {
				break
			}
			continue
		}
		input, _ := WitnessInput(req, ModeSequential, seqIdx, prevSig)
		if err := VerifyIndividual(entry.Pubkey, input, sig); err != nil {
			errs = append(errs,
				fmt.Sprintf("[seq=%d w=%d %s] individual verify: %v",
					seqIdx, entry.Index, entry.Label, err))
			continue
		}
		pubBytes, _ := entry.Pubkey.MarshalBinary()
		chain = append(chain, WitnessSignature{
			WitnessIndex: entry.Index,
			Pubkey:       pubBytes,
			Signature:    sig,
		})
		prevSig = sig
		if len(chain) >= cfg.Threshold {
			break
		}
	}
	if len(chain) < cfg.Threshold {
		return nil, fmt.Errorf("daq/client: sequential chain stalled at %d of %d; failures: %s",
			len(chain), cfg.Threshold, joinReasons(errs))
	}
	return &Ticket{
		Request:     *req,
		Mode:        ModeSequential,
		Threshold:   cfg.Threshold,
		RosterSize:  len(roster),
		Witnesses:   chain,
		CreatedAtMs: time.Now().UnixMilli(),
	}, nil
}

func postWitness(ctx context.Context, http *http.Client, entry RosterEntry, req *Request, mode Mode, seqIdx int, prevSig []byte) ([]byte, error) {
	body := WitnessRequestJSON{
		OpID:           req.OpID,
		OpHashHex:      hex.EncodeToString(req.OpHash),
		AgentPubkeyHex: hex.EncodeToString(req.AgentPubkey),
		AgentSigHex:    hex.EncodeToString(req.AgentSignature),
		DrandChain:     req.DrandChain,
		DrandRound:     req.DrandRound,
		DrandSigHex:    hex.EncodeToString(req.DrandSignature),
		RequestedAtMs:  req.RequestedAtMs,
		Mode:           mode.String(),
		SeqIndex:       seqIdx,
	}
	if mode == ModeSequential && seqIdx > 0 {
		body.PrevSigHex = hex.EncodeToString(prevSig)
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return postSignURL(ctx, http, entry.URL, entry.AuthToken, buf)
}

func postSignURL(ctx context.Context, c *http.Client, url, authToken string, body []byte) ([]byte, error) {
	r, err := httpNewRequest(ctx, http.MethodPost, url+"/daq/sign", body)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		r.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytesToTrim(bodyBytes, 256))
	}
	var reply WitnessResponseJSON
	if err := json.Unmarshal(bodyBytes, &reply); err != nil {
		return nil, fmt.Errorf("decode reply: %w", err)
	}
	sig, err := hex.DecodeString(reply.SignatureHex)
	if err != nil || len(sig) != SignatureSize {
		return nil, errors.New("witness returned malformed signature")
	}
	return sig, nil
}

func httpNewRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "963causal-agent/daq-client")
	return r, nil
}

func sortedRoster(in []RosterEntry) []RosterEntry {
	out := make([]RosterEntry, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

func joinReasons(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	out := items[0]
	for _, s := range items[1:] {
		out += "; " + s
	}
	return out
}

func bytesToTrim(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

// VerifyTicket is the server-side equivalent of RequestQuorum.
// Verifies:
//
//   1. Agent Ed25519 signature over the canonical request bytes.
//   2. Threshold is satisfied (k signatures, whether aggregated or
//      sequential).
//   3. In parallel mode: BDN aggregate verifies against the subset
//      of pubkeys selected by AggMask.
//   4. In sequential mode: every (witness, signature) pair verifies
//      in order, AND each signature binds the previous one.
//
// Returns nil on success. On failure the error string is suitable
// for logging / alerting.
func VerifyTicket(ticket *Ticket, roster []*PublicKey) error {
	if ticket == nil {
		return errors.New("daq/verify: nil ticket")
	}
	if err := VerifyAgentSignature(&ticket.Request); err != nil {
		return err
	}
	if ticket.Threshold < 1 || ticket.Threshold > len(roster) {
		return fmt.Errorf("daq/verify: threshold %d outside [1, %d]",
			ticket.Threshold, len(roster))
	}

	switch ticket.Mode {
	case ModeParallel:
		if len(ticket.AggSignature) == 0 || len(ticket.AggMask) == 0 {
			return errors.New("daq/verify: parallel ticket missing aggregate")
		}
		input, err := WitnessInput(&ticket.Request, ModeParallel, 0, nil)
		if err != nil {
			return err
		}
		return VerifyAggregate(roster, ticket.AggMask, ticket.AggSignature, input, ticket.Threshold)
	case ModeSequential:
		if len(ticket.Witnesses) < ticket.Threshold {
			return fmt.Errorf("daq/verify: sequential chain length %d < threshold %d",
				len(ticket.Witnesses), ticket.Threshold)
		}
		var prevSig []byte
		seenIdx := make(map[int]bool, len(ticket.Witnesses))
		for seqIdx, ws := range ticket.Witnesses {
			if ws.WitnessIndex < 0 || ws.WitnessIndex >= len(roster) {
				return fmt.Errorf("daq/verify: witness index %d out of roster", ws.WitnessIndex)
			}
			if seenIdx[ws.WitnessIndex] {
				return fmt.Errorf("daq/verify: duplicate witness index %d", ws.WitnessIndex)
			}
			seenIdx[ws.WitnessIndex] = true
			expectedPubBytes, _ := roster[ws.WitnessIndex].MarshalBinary()
			if !bytesEqualConst(ws.Pubkey, expectedPubBytes) {
				return fmt.Errorf("daq/verify: witness %d pubkey mismatch with roster", ws.WitnessIndex)
			}
			input, err := WitnessInput(&ticket.Request, ModeSequential, seqIdx, prevSig)
			if err != nil {
				return err
			}
			if err := VerifyIndividual(roster[ws.WitnessIndex], input, ws.Signature); err != nil {
				return fmt.Errorf("daq/verify: witness seq=%d idx=%d sig: %w",
					seqIdx, ws.WitnessIndex, err)
			}
			prevSig = ws.Signature
		}
		return nil
	default:
		return fmt.Errorf("daq/verify: unknown mode %v", ticket.Mode)
	}
}
