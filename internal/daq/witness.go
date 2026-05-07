package daq

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HashAuthToken returns the SHA-256 of a bearer token, in the exact
// form the witness stores and compares. Helper for roster tooling
// that provisions tokens.
func HashAuthToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// WitnessConfig bundles everything a witness needs to answer a DAQ
// request. A production deployment persists the private key to disk
// via SaveWitnessKey; in-memory-only witnesses (tests, smoke tools)
// pass the *PrivateKey directly.
type WitnessConfig struct {
	Index       int
	Label       string
	Priv        *PrivateKey
	Drand       *drandClient
	// MaxRoundLag is how many drand rounds of skew the witness will
	// tolerate between the request-supplied round and the witness's
	// own view. ±2 on fastnet ≈ ±6 s, matching the ADR-004 bound.
	MaxRoundLag int
	// VerifyDrand enables the independent drand cross-fetch +
	// BLS-signature verification step. Smoke tests disable this
	// when running against fake drand injected directly into the
	// request; production witnesses keep it on.
	VerifyDrand bool
	// DrandChainPubkey is the pinned 96-byte G2 public key of the
	// drand chain this witness trusts. Nil means "fall back to
	// WellKnownFastnetChainPubkey"; set explicitly when running on
	// a non-LoE chain.
	DrandChainPubkey []byte
	// AuthTokenHash is the expected Authorization: Bearer <token>
	// after SHA-256. Empty ⇒ auth disabled (MVP / smoke tests);
	// production witnesses always set this so casual network
	// scanners cannot feed bogus requests at the signer.
	AuthTokenHash []byte
}

// WitnessRequestJSON is the wire format witnesses accept on their
// POST /daq/sign endpoint. All byte fields are lowercase hex to keep
// the protocol debuggable with curl.
type WitnessRequestJSON struct {
	OpID            string `json:"op_id"`
	OpHashHex       string `json:"op_hash"`
	AgentPubkeyHex  string `json:"agent_pubkey"`
	AgentSigHex     string `json:"agent_sig"`
	DrandChain      string `json:"drand_chain"`
	DrandRound      uint64 `json:"drand_round"`
	DrandSigHex     string `json:"drand_sig"`
	RequestedAtMs   int64  `json:"requested_at_ms"`
	Mode            string `json:"mode"`              // "parallel" or "sequential"
	SeqIndex        int    `json:"seq_index"`         // 0-based position in chain mode
	PrevSigHex      string `json:"prev_sig,omitempty"` // only when seq_index > 0
}

// WitnessResponseJSON is the wire format the witness returns on a
// successful sign. On failure the HTTP status is >= 400 and the body
// is a plain text reason.
type WitnessResponseJSON struct {
	WitnessIndex int    `json:"witness_index"`
	Label        string `json:"label"`
	PubkeyHex    string `json:"pubkey"`
	SignatureHex string `json:"signature"`
	SignedAtMs   int64  `json:"signed_at_ms"`
}

// SaveWitnessKey writes a 32-byte BLS private key to `path` with
// mode 0600. Safe to call over an existing file; the rename is atomic.
func SaveWitnessKey(path string, priv *PrivateKey) error {
	b, err := priv.MarshalBinary()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadOrCreateWitnessKey loads a BLS private key from `path`, or
// generates and persists a fresh one if the file is missing. Returns
// the private key, its public, and whether a fresh key was minted.
func LoadOrCreateWitnessKey(path string) (*PrivateKey, *PublicKey, bool, error) {
	if path == "" {
		priv, pub, err := GenerateKeyPair()
		return priv, pub, true, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, false, fmt.Errorf("daq/witness: read key: %w", err)
		}
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			return nil, nil, false, err
		}
		if err := SaveWitnessKey(path, priv); err != nil {
			return nil, nil, false, err
		}
		return priv, pub, true, nil
	}
	priv, err := UnmarshalPrivateKey(raw)
	if err != nil {
		return nil, nil, false, err
	}
	return priv, priv.Public(), false, nil
}

// WitnessHandler returns the http.Handler that implements the witness
// signing protocol. The handler performs, in order:
//
//   1. Decode the JSON body; reject any field-size mismatch.
//   2. Re-check the agent's Ed25519 signature over the canonical
//      request bytes. A witness MUST NOT sign for an agent that
//      cannot prove authorship of the request.
//   3. If VerifyDrand is enabled, fetch the same round from the
//      witness's view of drand and confirm the signature matches.
//   4. Check the round's freshness window.
//   5. Compute the canonical witness input for the requested mode
//      (parallel vs sequential) and produce the BDN signature.
//
// Any failure returns 4xx with a plain-text reason so operator-side
// debugging can grep logs.
func WitnessHandler(cfg WitnessConfig) http.Handler {
	mux := http.NewServeMux()

	pubBytes, err := cfg.Priv.Public().MarshalBinary()
	if err != nil {
		// Panic here is acceptable: a witness with an unmarshallable
		// key is dead on arrival; we want the process to crash loud
		// rather than serve traffic.
		panic(fmt.Errorf("daq/witness: marshal pub: %w", err))
	}
	pubHex := hex.EncodeToString(pubBytes)

	mux.HandleFunc("/daq/info", func(w http.ResponseWriter, r *http.Request) {
		// Unauthenticated: lets the agent discover the witness's
		// pubkey + label during roster bootstrap.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"witness_index": cfg.Index,
			"label":         cfg.Label,
			"pubkey":        pubHex,
			"drand_chain":   cfg.Drand.Chain(),
		})
	})

	mux.HandleFunc("/daq/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Bearer-token auth. When AuthTokenHash is empty the witness
		// runs in no-auth mode (acceptable for the local 5-on-one-
		// host topology before W7; production geographic witnesses
		// must always set it via --auth-token or
		// CAUSAL_963_WITNESS_AUTH_TOKEN).
		if len(cfg.AuthTokenHash) > 0 {
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			presented := strings.TrimPrefix(authz, "Bearer ")
			presentedHash := HashAuthToken(presented)
			if subtle.ConstantTimeCompare(presentedHash, cfg.AuthTokenHash) != 1 {
				http.Error(w, "bad bearer token", http.StatusUnauthorized)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req WitnessRequestJSON
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}

		parsed, err := parseWitnessRequest(&req)
		if err != nil {
			http.Error(w, "parse: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := VerifyAgentSignature(parsed.Request); err != nil {
			http.Error(w, "agent sig: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if cfg.VerifyDrand {
			// Primary defence: cryptographically verify the drand
			// signature against the pinned chain pubkey. This kills
			// MITM on *every* drand relay simultaneously; a forged
			// beacon would have to break BLS12-381 on G2, not just
			// poison one HTTP response.
			chainPub := cfg.DrandChainPubkey
			if len(chainPub) == 0 {
				chainPub = ExpectedChainPubkey()
			}
			if err := VerifyDrandBeacon(parsed.Request.DrandRound,
				parsed.Request.DrandSignature, chainPub); err != nil {
				http.Error(w, "drand verify: "+err.Error(), http.StatusBadRequest)
				return
			}
			// Secondary defence: freshness. A BLS-valid-but-ancient
			// beacon would pass the check above but still be a
			// replay of an old attestation. We cross-fetch the same
			// round from our own relay view to compute "current
			// round at wall clock now" and enforce the ±lag bound.
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			info, err := cfg.Drand.Info(ctx)
			if err != nil {
				http.Error(w, "drand info: "+err.Error(), http.StatusBadGateway)
				return
			}
			maxLag := cfg.MaxRoundLag
			if maxLag == 0 {
				maxLag = 2
			}
			if err := CheckFreshness(info, parsed.Request.DrandRound, time.Now(), maxLag); err != nil {
				http.Error(w, "drand freshness: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		input, err := WitnessInput(parsed.Request, parsed.Mode, parsed.SeqIndex, parsed.PrevSig)
		if err != nil {
			http.Error(w, "witness input: "+err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := Sign(cfg.Priv, input)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := WitnessResponseJSON{
			WitnessIndex: cfg.Index,
			Label:        cfg.Label,
			PubkeyHex:    pubHex,
			SignatureHex: hex.EncodeToString(sig),
			SignedAtMs:   time.Now().UnixMilli(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

type parsedWitnessRequest struct {
	Request  *Request
	Mode     Mode
	SeqIndex int
	PrevSig  []byte
}

func parseWitnessRequest(r *WitnessRequestJSON) (*parsedWitnessRequest, error) {
	if r.OpID == "" {
		return nil, errors.New("op_id missing")
	}
	opHash, err := hex.DecodeString(r.OpHashHex)
	if err != nil || len(opHash) != 32 {
		return nil, errors.New("op_hash must be 32B hex")
	}
	agentPub, err := hex.DecodeString(r.AgentPubkeyHex)
	if err != nil || len(agentPub) != 32 {
		return nil, errors.New("agent_pubkey must be 32B hex")
	}
	agentSig, err := hex.DecodeString(r.AgentSigHex)
	if err != nil || len(agentSig) != 64 {
		return nil, errors.New("agent_sig must be 64B hex")
	}
	drandSig, err := hex.DecodeString(r.DrandSigHex)
	if err != nil || len(drandSig) != 48 {
		return nil, errors.New("drand_sig must be 48B hex")
	}

	mode := ModeParallel
	switch r.Mode {
	case "", "parallel":
		mode = ModeParallel
	case "sequential":
		mode = ModeSequential
	default:
		return nil, fmt.Errorf("unknown mode %q", r.Mode)
	}

	var prevSig []byte
	if mode == ModeSequential && r.SeqIndex > 0 {
		prevSig, err = hex.DecodeString(r.PrevSigHex)
		if err != nil || len(prevSig) != 48 {
			return nil, errors.New("prev_sig must be 48B hex for seq_index > 0")
		}
	}

	return &parsedWitnessRequest{
		Request: &Request{
			OpID:           r.OpID,
			OpHash:         opHash,
			AgentPubkey:    agentPub,
			AgentSignature: agentSig,
			DrandChain:     r.DrandChain,
			DrandRound:     r.DrandRound,
			DrandSignature: drandSig,
			RequestedAtMs:  r.RequestedAtMs,
		},
		Mode:     mode,
		SeqIndex: r.SeqIndex,
		PrevSig:  prevSig,
	}, nil
}

// bytesEqualConst is a small constant-time compare for drand sigs.
// Intentionally separate from fuzzy.equalConstantTime so daq has no
// implicit dependency on the puf package.
func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
