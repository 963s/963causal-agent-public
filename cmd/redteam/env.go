package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/963causal/agent/internal/daq"
	blsbn "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

// drandMsgForRound mirrors internal/daq.drandMsgBLSUnchained. The
// daq package keeps the helper unexported (it is an implementation
// detail of the verifier), but the red-team harness signs its own
// fake chain and therefore needs access to the exact message
// construction. A four-line copy here is safer than widening the
// public surface of the daq package for the sole benefit of the
// test harness.
func drandMsgForRound(round uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], round)
	sum := sha256.Sum256(buf[:])
	return sum[:]
}

// Env carries every bit of state the attacks share: five BDN
// witnesses running in-process on random loopback ports, their
// BDN privates + pubs, a synthetic agent Ed25519 identity, a
// deterministic fake drand chain whose private scalar the harness
// holds (so it can forge a "valid" beacon sig under a chain pubkey
// we also control), and the HTTP client the client-side attacks
// use.
//
// We deliberately DO NOT use the real drand endpoint here: the
// purpose of the harness is to exercise our verification code, not
// drand's. Holding our own chain key lets attacks produce a
// cryptographically valid beacon AND a deliberately tampered one
// with no network flakiness.
type Env struct {
	Witnesses   []*witness
	Roster      []daq.RosterEntry
	RosterPubs  []*daq.PublicKey
	Threshold   int
	AgentPub    ed25519.PublicKey
	AgentPriv   ed25519.PrivateKey
	FakeDrandSk []byte // 32B; the "chain's" secret (we control it)
	FakeChainPub []byte // 96B G2 pubkey corresponding to FakeDrandSk
	HTTP        *http.Client
	// Round + Signature we hand out at attack time. Updated inside
	// BuildRequest() so freshness checks behave realistically.
	CurrentRound uint64
}

type witness struct {
	index  int
	label  string
	priv   *daq.PrivateKey
	pub    *daq.PublicKey
	token  string
	addr   string
	srv    *http.Server
	ln     net.Listener
}

// NewEnv boots a fresh environment. On failure it closes whatever
// already came up before returning — callers can treat the err as
// final.
func NewEnv(ctx context.Context) (*Env, error) {
	env := &Env{
		Threshold: 3,
		HTTP:      &http.Client{Timeout: 3 * time.Second},
	}

	// ---- Fake drand chain ---------------------------------------------------
	// We sign beacons with a BLS key we hold, then pin the
	// corresponding public half so VerifyDrandBeacon will accept
	// our "signed" round. This lets attacks prove the verifier
	// rejects bit-flips without depending on api.drand.sh.
	suite := blsbn.NewBLS12381Suite()
	scheme := bls.NewSchemeOnG1(suite)
	sk, pk := scheme.NewKeyPair(suite.RandomStream())
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal fake chain pub: %w", err)
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal fake chain sk: %w", err)
	}
	env.FakeDrandSk = skBytes
	env.FakeChainPub = pkBytes

	// ---- Agent identity -----------------------------------------------------
	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agent keypair: %w", err)
	}
	env.AgentPub = apub
	env.AgentPriv = apriv

	// ---- Five witnesses -----------------------------------------------------
	for i := 0; i < 5; i++ {
		priv, pub, err := daq.GenerateKeyPair()
		if err != nil {
			env.Close()
			return nil, fmt.Errorf("witness %d keygen: %w", i, err)
		}
		var tokBytes [16]byte
		if _, err := rand.Read(tokBytes[:]); err != nil {
			env.Close()
			return nil, fmt.Errorf("witness %d token: %w", i, err)
		}
		token := hex.EncodeToString(tokBytes[:])

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			env.Close()
			return nil, fmt.Errorf("witness %d listen: %w", i, err)
		}
		handler := daq.WitnessHandler(daq.WitnessConfig{
			Index:            i,
			Label:            fmt.Sprintf("rt-w%d", i),
			Priv:             priv,
			Drand:            daq.NewDrandClient("", nil), // unused because VerifyDrand = false
			MaxRoundLag:      4,
			// The harness supplies its own "fresh" drand round; we
			// short-circuit the HTTPS cross-fetch because we do NOT
			// want attacks to depend on api.drand.sh being up.
			VerifyDrand:      false,
			DrandChainPubkey: env.FakeChainPub,
			AuthTokenHash:    daq.HashAuthToken(token),
		})
		srv := &http.Server{
			Handler:      handler,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 3 * time.Second,
		}
		go func() { _ = srv.Serve(ln) }()

		env.Witnesses = append(env.Witnesses, &witness{
			index:  i,
			label:  fmt.Sprintf("rt-w%d", i),
			priv:   priv,
			pub:    pub,
			token:  token,
			addr:   ln.Addr().String(),
			srv:    srv,
			ln:     ln,
		})
		env.Roster = append(env.Roster, daq.RosterEntry{
			Index:     i,
			Label:     fmt.Sprintf("rt-w%d", i),
			URL:       "http://" + ln.Addr().String(),
			Pubkey:    pub,
			AuthToken: token,
		})
		env.RosterPubs = append(env.RosterPubs, pub)
	}

	// Give Serve() a tick to start accepting before any attack runs.
	time.Sleep(40 * time.Millisecond)

	// ---- Round 1 of the fake chain -----------------------------------------
	env.CurrentRound = 42
	return env, nil
}

// Close stops every in-process witness. Idempotent.
func (e *Env) Close() {
	if e == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, w := range e.Witnesses {
		if w.srv != nil {
			_ = w.srv.Shutdown(ctx)
		}
	}
}

// SignFakeDrand produces a BLS G1 signature on the given round under
// the harness's chain private key. The returned sig verifies under
// Env.FakeChainPub exactly the way VerifyDrandBeacon expects.
func (e *Env) SignFakeDrand(round uint64) ([]byte, error) {
	// Reconstruct the scalar from the stashed bytes.
	suite := blsbn.NewBLS12381Suite()
	scheme := bls.NewSchemeOnG1(suite)
	scalar := suite.G2().Scalar()
	if err := scalar.UnmarshalBinary(e.FakeDrandSk); err != nil {
		return nil, err
	}
	// The message must match VerifyDrandBeacon's construction: the
	// 32-byte SHA-256 of the big-endian uint64 round.
	msg := drandMsgForRound(round)
	return scheme.Sign(scalar, msg)
}

// BuildRequest assembles a well-formed DAQ Request signed by the
// harness's agent identity, anchored to the harness's fake drand
// chain. Attacks tweak fields of the returned Request to exercise
// specific verification paths.
func (e *Env) BuildRequest(opID string, opPayload []byte) (*daq.Request, error) {
	sig, err := e.SignFakeDrand(e.CurrentRound)
	if err != nil {
		return nil, err
	}
	req := &daq.Request{
		OpID:           opID,
		OpHash:         daq.HashOperationPayload(opPayload),
		AgentPubkey:    append([]byte(nil), e.AgentPub...),
		DrandChain:     "redteam/fake-chain",
		DrandRound:     e.CurrentRound,
		DrandSignature: sig,
		RequestedAtMs:  time.Now().UnixMilli(),
	}
	canon, err := daq.CanonicalRequestBytes(req)
	if err != nil {
		return nil, err
	}
	req.AgentSignature = ed25519.Sign(e.AgentPriv, canon)
	return req, nil
}
