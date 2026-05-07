// Command daq-verifier is the loopback HTTP service the Next.js
// control plane calls whenever it needs to either (a) run a fresh
// DAQ attestation to gate a sensitive operation, or (b) re-verify a
// ticket it already has on disk.
//
// Why a separate Go process and not a TypeScript port of the BDN
// verifier: the BDN aggregate scheme has a coefficient-derivation
// step that touches blake2s, a pairing DST kyber picked on its own
// (BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_), and a "coef+1" convention
// that is easy to miss when reimplementing. Running Go code we
// already ship unit-tested (see internal/daq/bls_test.go) keeps the
// cryptographic trust surface of the whole stack inside one
// codebase. The HTTP hop is 127.0.0.1-only, adds <1 ms, and lets
// Next.js stay in its comfort zone.
//
// Endpoints:
//
//   POST /execute  — orchestrate a full DAQ round: build request,
//                    fan-out to the supplied witnesses, aggregate,
//                    verify, return the ticket.
//
//   POST /verify   — re-verify a stored ticket against a supplied
//                    roster. Used on demand from the UI when an
//                    operator clicks "re-check" on an old record.
//
//   GET  /healthz  — liveness probe for PM2.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/963causal/agent/internal/daq"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:17090", "HTTP listen address (loopback only)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/execute", handleExecute)
	mux.HandleFunc("/verify", handleVerify)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("daq-verifier: listen %s: %v", *addr, err)
	}
	log.Printf("daq-verifier ready on http://%s", ln.Addr().String())
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("daq-verifier: serve: %v", err)
	}
}

// -----------------------------------------------------------------
//  Shared request shapes
// -----------------------------------------------------------------

// witnessSpec is how the caller describes one witness in the roster.
// pubkey_hex is the 96-byte BDN G2 compressed point. auth_token is
// the plaintext bearer the verifier attaches on every /daq/sign
// call to that witness; empty = no-auth witness.
type witnessSpec struct {
	Index     int    `json:"index"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	PubkeyHex string `json:"pubkey"`
	AuthToken string `json:"auth_token,omitempty"`
}

// executeRequest is the input to POST /execute. `server_priv_hex`
// is the 32-byte Ed25519 seed the server uses as its DAQ-agent
// identity; `server_pub_hex` must match ed25519 derivation from it
// (the verifier double-checks, so the caller cannot fool the audit
// trail by uploading a mismatched pair).
type executeRequest struct {
	Roster         []witnessSpec `json:"roster"`
	Threshold      int           `json:"threshold"`
	Mode           string        `json:"mode"` // "parallel" | "sequential"
	OpID           string        `json:"op_id"`
	OpPayloadHex   string        `json:"op_payload"`
	ServerPubHex   string        `json:"server_pubkey"`
	ServerPrivHex  string        `json:"server_privkey"`
	DrandChain     string        `json:"drand_chain,omitempty"`
	WitnessTimeout int           `json:"witness_timeout_ms,omitempty"`
}

// executeResponse carries the final ticket (if built) plus the
// verifier's own yes/no verdict — so the caller never has to trust
// the witnesses blindly.
type executeResponse struct {
	OK            bool          `json:"ok"`
	Reason        string        `json:"reason,omitempty"`
	Ticket        *ticketJSON   `json:"ticket,omitempty"`
	DrandRound    uint64        `json:"drand_round,omitempty"`
	Participants  []int         `json:"participants,omitempty"`
	DurationMs    int64         `json:"duration_ms"`
}

// ticketJSON is the wire form of daq.Ticket. All byte slices are
// lowercase hex so the caller can persist it as-is or redisplay in
// the UI without an extra decode step.
type ticketJSON struct {
	OpID            string             `json:"op_id"`
	OpHashHex       string             `json:"op_hash"`
	AgentPubkeyHex  string             `json:"agent_pubkey"`
	AgentSigHex     string             `json:"agent_signature"`
	DrandChain      string             `json:"drand_chain"`
	DrandRound      uint64             `json:"drand_round"`
	DrandSigHex     string             `json:"drand_signature"`
	RequestedAtMs   int64              `json:"requested_at_ms"`
	Mode            string             `json:"mode"`
	Threshold       int                `json:"threshold"`
	RosterSize      int                `json:"roster_size"`
	Witnesses       []witnessSigJSON   `json:"witnesses"`
	AggSignatureHex string             `json:"agg_signature,omitempty"`
	AggMaskHex      string             `json:"agg_mask,omitempty"`
	CreatedAtMs     int64              `json:"created_at_ms"`
}

type witnessSigJSON struct {
	WitnessIndex int    `json:"witness_index"`
	PubkeyHex    string `json:"pubkey"`
	SignatureHex string `json:"signature"`
}

// verifyRequest is the input to POST /verify. `ticket` is the JSON
// form of the ticket previously emitted by /execute; `roster` is the
// (possibly rotated) current list of witness pubkeys the caller
// wants the ticket checked against.
type verifyRequest struct {
	Roster []witnessSpec `json:"roster"`
	Ticket ticketJSON    `json:"ticket"`
}

type verifyResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// -----------------------------------------------------------------
//  /execute — full orchestration
// -----------------------------------------------------------------

func handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req executeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}

	t0 := time.Now()

	// -- Parse roster + Ed25519 keypair
	entries, rosterPubs, err := parseRoster(req.Roster)
	if err != nil {
		respondExecuteErr(w, "roster: "+err.Error(), time.Since(t0))
		return
	}
	if req.Threshold < 1 || req.Threshold > len(entries) {
		respondExecuteErr(w, fmt.Sprintf("threshold %d outside [1, %d]", req.Threshold, len(entries)), time.Since(t0))
		return
	}
	serverPub, err := hex.DecodeString(req.ServerPubHex)
	if err != nil || len(serverPub) != ed25519.PublicKeySize {
		respondExecuteErr(w, "server_pubkey must be 32B hex", time.Since(t0))
		return
	}
	serverSeed, err := hex.DecodeString(req.ServerPrivHex)
	if err != nil || len(serverSeed) != ed25519.SeedSize {
		respondExecuteErr(w, "server_privkey must be 32B hex (ed25519 seed)", time.Since(t0))
		return
	}
	serverPriv := ed25519.NewKeyFromSeed(serverSeed)
	// Defence-in-depth: confirm the supplied public half matches the
	// derived one so the audit trail cannot be seeded with a
	// mismatched pair (which would later make every ticket fail
	// verify silently on some callers).
	derivedPub := serverPriv.Public().(ed25519.PublicKey)
	for i := 0; i < ed25519.PublicKeySize; i++ {
		if derivedPub[i] != serverPub[i] {
			respondExecuteErr(w, "server_pubkey does not match derivation from server_privkey", time.Since(t0))
			return
		}
	}

	opPayload, err := hex.DecodeString(req.OpPayloadHex)
	if err != nil {
		respondExecuteErr(w, "op_payload must be hex", time.Since(t0))
		return
	}

	mode := daq.ModeParallel
	switch req.Mode {
	case "", "parallel":
		mode = daq.ModeParallel
	case "sequential":
		mode = daq.ModeSequential
	default:
		respondExecuteErr(w, "unknown mode "+req.Mode, time.Since(t0))
		return
	}

	witTimeout := 6 * time.Second
	if req.WitnessTimeout > 0 {
		witTimeout = time.Duration(req.WitnessTimeout) * time.Millisecond
	}

	chain := req.DrandChain
	if chain == "" {
		chain = daq.DefaultDrandChain
	}

	// -- Build request against fresh drand
	drand := daq.NewDrandClient(chain, nil)
	buildCtx, buildCancel := context.WithTimeout(r.Context(), 10*time.Second)
	daqReq, err := daq.BuildRequest(buildCtx, drand, serverPub, serverPriv,
		daq.Operation{ID: req.OpID, Payload: opPayload})
	buildCancel()
	if err != nil {
		respondExecuteErr(w, "build request: "+err.Error(), time.Since(t0))
		return
	}

	// -- Fan-out / collect quorum
	clientCfg := daq.ClientConfig{
		Roster:    entries,
		Threshold: req.Threshold,
		Mode:      mode,
		Drand:     drand,
		HTTP: &http.Client{
			Timeout: witTimeout,
		},
	}
	reqCtx, reqCancel := context.WithTimeout(r.Context(), 30*time.Second)
	ticket, err := daq.RequestQuorum(reqCtx, clientCfg, daqReq)
	reqCancel()
	if err != nil {
		respondExecuteErr(w, "quorum: "+err.Error(), time.Since(t0))
		return
	}

	// -- Self-verify before returning. If we cannot verify our own
	// ticket, something is severely wrong and we'd rather fail loud
	// than hand the caller a ticket the DB store would later reject.
	if err := daq.VerifyTicket(ticket, rosterPubs); err != nil {
		respondExecuteErr(w, "self-verify: "+err.Error(), time.Since(t0))
		return
	}

	participants := collectParticipants(ticket)

	resp := executeResponse{
		OK:           true,
		Ticket:       ticketToJSON(ticket),
		DrandRound:   daqReq.DrandRound,
		Participants: participants,
		DurationMs:   time.Since(t0).Milliseconds(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// -----------------------------------------------------------------
//  /verify — re-verify a stored ticket
// -----------------------------------------------------------------

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	_, rosterPubs, err := parseRoster(req.Roster)
	if err != nil {
		respondVerify(w, false, "roster: "+err.Error())
		return
	}
	ticket, err := ticketFromJSON(&req.Ticket)
	if err != nil {
		respondVerify(w, false, "ticket: "+err.Error())
		return
	}
	if err := daq.VerifyTicket(ticket, rosterPubs); err != nil {
		respondVerify(w, false, err.Error())
		return
	}
	respondVerify(w, true, "")
}

// -----------------------------------------------------------------
//  Helpers
// -----------------------------------------------------------------

func parseRoster(in []witnessSpec) ([]daq.RosterEntry, []*daq.PublicKey, error) {
	if len(in) == 0 {
		return nil, nil, fmt.Errorf("empty roster")
	}
	entries := make([]daq.RosterEntry, len(in))
	pubs := make([]*daq.PublicKey, len(in))
	sorted := append([]witnessSpec(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })
	for i, ws := range sorted {
		if ws.Index != i {
			return nil, nil, fmt.Errorf("roster indices must be contiguous 0..n-1 (position %d has index=%d)", i, ws.Index)
		}
		raw, err := hex.DecodeString(ws.PubkeyHex)
		if err != nil || len(raw) != daq.PubkeySize {
			return nil, nil, fmt.Errorf("roster[%d] pubkey must be %d-byte hex", ws.Index, daq.PubkeySize)
		}
		pub, err := daq.UnmarshalPublicKey(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("roster[%d] unmarshal: %w", ws.Index, err)
		}
		entries[i] = daq.RosterEntry{
			Index:     ws.Index,
			Label:     ws.Label,
			URL:       ws.URL,
			Pubkey:    pub,
			AuthToken: ws.AuthToken,
		}
		pubs[i] = pub
	}
	return entries, pubs, nil
}

func collectParticipants(t *daq.Ticket) []int {
	if t == nil {
		return nil
	}
	if t.Mode == daq.ModeParallel && len(t.AggMask) > 0 {
		// Flatten the mask to indices.
		var out []int
		for i := 0; i < t.RosterSize; i++ {
			if t.AggMask[i/8]&(1<<uint(i%8)) != 0 {
				out = append(out, i)
			}
		}
		return out
	}
	out := make([]int, 0, len(t.Witnesses))
	for _, ws := range t.Witnesses {
		out = append(out, ws.WitnessIndex)
	}
	return out
}

func ticketToJSON(t *daq.Ticket) *ticketJSON {
	out := &ticketJSON{
		OpID:           t.Request.OpID,
		OpHashHex:      hex.EncodeToString(t.Request.OpHash),
		AgentPubkeyHex: hex.EncodeToString(t.Request.AgentPubkey),
		AgentSigHex:    hex.EncodeToString(t.Request.AgentSignature),
		DrandChain:     t.Request.DrandChain,
		DrandRound:     t.Request.DrandRound,
		DrandSigHex:    hex.EncodeToString(t.Request.DrandSignature),
		RequestedAtMs:  t.Request.RequestedAtMs,
		Mode:           t.Mode.String(),
		Threshold:      t.Threshold,
		RosterSize:     t.RosterSize,
		CreatedAtMs:    t.CreatedAtMs,
	}
	for _, ws := range t.Witnesses {
		out.Witnesses = append(out.Witnesses, witnessSigJSON{
			WitnessIndex: ws.WitnessIndex,
			PubkeyHex:    hex.EncodeToString(ws.Pubkey),
			SignatureHex: hex.EncodeToString(ws.Signature),
		})
	}
	if len(t.AggSignature) > 0 {
		out.AggSignatureHex = hex.EncodeToString(t.AggSignature)
	}
	if len(t.AggMask) > 0 {
		out.AggMaskHex = hex.EncodeToString(t.AggMask)
	}
	return out
}

func ticketFromJSON(j *ticketJSON) (*daq.Ticket, error) {
	opHash, err := hex.DecodeString(j.OpHashHex)
	if err != nil {
		return nil, fmt.Errorf("op_hash: %w", err)
	}
	agentPub, err := hex.DecodeString(j.AgentPubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("agent_pubkey: %w", err)
	}
	agentSig, err := hex.DecodeString(j.AgentSigHex)
	if err != nil {
		return nil, fmt.Errorf("agent_signature: %w", err)
	}
	drandSig, err := hex.DecodeString(j.DrandSigHex)
	if err != nil {
		return nil, fmt.Errorf("drand_signature: %w", err)
	}
	var mode daq.Mode
	switch j.Mode {
	case "parallel":
		mode = daq.ModeParallel
	case "sequential":
		mode = daq.ModeSequential
	default:
		return nil, fmt.Errorf("unknown mode %q", j.Mode)
	}
	ws := make([]daq.WitnessSignature, len(j.Witnesses))
	for i, w := range j.Witnesses {
		pub, err := hex.DecodeString(w.PubkeyHex)
		if err != nil {
			return nil, fmt.Errorf("witness[%d] pubkey: %w", i, err)
		}
		sig, err := hex.DecodeString(w.SignatureHex)
		if err != nil {
			return nil, fmt.Errorf("witness[%d] signature: %w", i, err)
		}
		ws[i] = daq.WitnessSignature{
			WitnessIndex: w.WitnessIndex,
			Pubkey:       pub,
			Signature:    sig,
		}
	}
	var aggSig, aggMask []byte
	if j.AggSignatureHex != "" {
		if aggSig, err = hex.DecodeString(j.AggSignatureHex); err != nil {
			return nil, fmt.Errorf("agg_signature: %w", err)
		}
	}
	if j.AggMaskHex != "" {
		if aggMask, err = hex.DecodeString(j.AggMaskHex); err != nil {
			return nil, fmt.Errorf("agg_mask: %w", err)
		}
	}
	return &daq.Ticket{
		Request: daq.Request{
			OpID:           j.OpID,
			OpHash:         opHash,
			AgentPubkey:    agentPub,
			AgentSignature: agentSig,
			DrandChain:     j.DrandChain,
			DrandRound:     j.DrandRound,
			DrandSignature: drandSig,
			RequestedAtMs:  j.RequestedAtMs,
		},
		Mode:         mode,
		Threshold:    j.Threshold,
		RosterSize:   j.RosterSize,
		Witnesses:    ws,
		AggSignature: aggSig,
		AggMask:      aggMask,
		CreatedAtMs:  j.CreatedAtMs,
	}, nil
}

func respondExecuteErr(w http.ResponseWriter, reason string, elapsed time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	// Always 200 so Next.js can inspect reason; the ok flag carries
	// the verdict. True HTTP errors (4xx/5xx) only happen on
	// malformed requests handled earlier.
	_ = json.NewEncoder(w).Encode(executeResponse{
		OK:         false,
		Reason:     reason,
		DurationMs: elapsed.Milliseconds(),
	})
}

func respondVerify(w http.ResponseWriter, ok bool, reason string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verifyResponse{OK: ok, Reason: reason})
}
