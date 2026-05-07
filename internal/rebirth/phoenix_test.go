package rebirth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// TestPhoenixHappyPath: service S is born on host H1. H1 dies.
// Operator requests rebirth to H2. Three witnesses attest after
// the cool-down. Execute succeeds. VerifyLineage validates the
// full chain.
func TestPhoenixHappyPath(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	// ---- Record 0: initial birth of service S on H1 -----------
	birth, err := SealRequest("service-S", h1Pub, nil, opPriv, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("initial birth seal: %v", err)
	}
	birthAttests := attestAll(t, birth, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	r0, err := Execute(birth, birthAttests, 3,
		birth.RequestedAtMs+birth.CoolDownMs+1)
	if err != nil {
		t.Fatalf("birth execute: %v", err)
	}

	// ---- Record 1: rebirth from H1 → H2 after hardware failure
	rebirth, err := SealRequest("service-S", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("rebirth seal: %v", err)
	}
	rebirthAttests := attestAll(t, rebirth, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	r1, err := Execute(rebirth, rebirthAttests, 3,
		rebirth.RequestedAtMs+rebirth.CoolDownMs+1)
	if err != nil {
		t.Fatalf("rebirth execute: %v", err)
	}

	lineage := []LineageRecord{*r0, *r1}
	if err := VerifyLineage(lineage, [][]byte{opPub}, 1, 3); err != nil {
		t.Fatalf("verify lineage: %v", err)
	}
}

// TestPhoenixRejectsUnpinnedOperator models the core threat:
// an attacker generates their own operator keypair and issues a
// rebirth request. Witnesses whose pinned operator set does not
// include the attacker's pubkey MUST refuse to attest.
func TestPhoenixRejectsUnpinnedOperator(t *testing.T) {
	realOpPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	req, err := SealRequest("service-S", h2Pub, h1Pub, attackerPriv, time.Second)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := VerifyOperator(req, [][]byte{realOpPub}, 1); err == nil {
		t.Fatal("VerifyOperator accepted unpinned operator")
	}
}

// TestPhoenixBelowThreshold: with only k-1 attestations, Execute
// must refuse. Protects against an attacker who compromises
// k-1 witnesses and tries to rush a rebirth.
func TestPhoenixBelowThreshold(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	req, _ := SealRequest("service-S", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	attests := attestAll(t, req, wits, 2, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	if _, err := Execute(req, attests, 3, req.RequestedAtMs+req.CoolDownMs+1); !errors.Is(err, ErrRebirth) {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

// TestPhoenixCoolDownEnforced: even with k valid attestations, if
// the cool-down has not elapsed the control plane refuses to
// Execute. Protects against "operator key compromised AND
// witnesses compromised simultaneously" → attacker still has to
// wait out the cool-down, during which the legitimate operator
// can notice and revoke.
func TestPhoenixCoolDownEnforced(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	req, _ := SealRequest("service-S", h2Pub, h1Pub, opPriv, 60_000*time.Millisecond)
	attests := attestAll(t, req, wits, 3, []ed25519.PublicKey{opPub}, 60*time.Second)
	// Execute immediately (cool-down not elapsed).
	if _, err := Execute(req, attests, 3, req.RequestedAtMs+100); !errors.Is(err, ErrRebirth) {
		t.Fatalf("expected cool-down error, got %v", err)
	}
}

// TestPhoenixReplayRejected: the SAME attestation cannot be
// reused to endorse a DIFFERENT rebirth request. The attestation
// binds the request hash, so a swap breaks the signature.
func TestPhoenixReplayRejected(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	// Legit request: H1 → H2
	req1, _ := SealRequest("service-S", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	att1 := attestAll(t, req1, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)

	// Attacker's forged request: H1 → H3 (they control H3).
	// They try to reuse att1.
	req2, _ := SealRequest("service-S", h3Pub, h1Pub, opPriv, 10*time.Millisecond)
	if _, err := Execute(req2, att1, 3, req2.RequestedAtMs+req2.CoolDownMs+1); !errors.Is(err, ErrRebirth) {
		t.Fatalf("replay: expected verify error, got %v", err)
	}
}

// TestPhoenixDuplicateWitnessRejected catches an attacker who
// compromises one witness and submits its attestation k times.
func TestPhoenixDuplicateWitnessRejected(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	req, _ := SealRequest("service-S", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	observedAt := req.RequestedAtMs + req.CoolDownMs + 1
	single, err := Attest(req, [][]byte{opPub}, 1, wits[0].index, wits[0].priv, observedAt, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	dupAttests := []Attestation{*single, *single, *single}
	if _, err := Execute(req, dupAttests, 3, observedAt+1); !errors.Is(err, ErrRebirth) {
		t.Fatalf("duplicate: expected error, got %v", err)
	}
}

// TestPhoenixMultiOperatorHappyPath: 2-of-3 operator threshold
// succeeds with 2 legitimate operator signatures, fails with 1.
func TestPhoenixMultiOperatorHappyPath(t *testing.T) {
	op1Pub, op1Priv, _ := ed25519.GenerateKey(rand.Reader)
	op2Pub, op2Priv, _ := ed25519.GenerateKey(rand.Reader)
	op3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pinned := [][]byte{op1Pub, op2Pub, op3Pub}

	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// 2-of-3: two operators co-sign.
	req, err := SealRequestMultiOp("service-S", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv, op2Priv}, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("seal multi: %v", err)
	}
	if err := VerifyOperator(req, pinned, 2); err != nil {
		t.Fatalf("verify 2-of-3 happy path: %v", err)
	}
}

// TestPhoenixMultiOperatorSingleKeyCompromiseInsufficient is
// the core ADR-018 invariant: an attacker who compromises ONE
// operator key cannot rebirth on their own when the threshold
// is ≥ 2.
func TestPhoenixMultiOperatorSingleKeyCompromiseInsufficient(t *testing.T) {
	op1Pub, op1Priv, _ := ed25519.GenerateKey(rand.Reader)
	op2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	op3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pinned := [][]byte{op1Pub, op2Pub, op3Pub}

	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Attacker has stolen op1 only.
	req, _ := SealRequestMultiOp("service-S", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv}, 10*time.Millisecond)
	// Deployment policy is M = 2. A single legit signature must fail.
	if err := VerifyOperator(req, pinned, 2); !errors.Is(err, ErrRebirth) {
		t.Fatalf("expected ErrRebirth on single-op under M=2, got %v", err)
	}
}

// TestPhoenixMultiOperatorDuplicateSignerRejected ensures an
// attacker cannot satisfy "M distinct operators" by replaying
// the same signature M times.
func TestPhoenixMultiOperatorDuplicateSignerRejected(t *testing.T) {
	op1Pub, op1Priv, _ := ed25519.GenerateKey(rand.Reader)
	op2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pinned := [][]byte{op1Pub, op2Pub}

	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Legit 1-of-1 request with op1.
	req, _ := SealRequestMultiOp("service-S", h2Pub, h1Pub,
		[]ed25519.PrivateKey{op1Priv}, 10*time.Millisecond)
	// Attacker duplicates op1's signature to try to hit M=2.
	req.OperatorSignatures = append(req.OperatorSignatures, req.OperatorSignatures[0])
	if err := VerifyOperator(req, pinned, 2); !errors.Is(err, ErrRebirth) {
		t.Fatalf("expected ErrRebirth on duplicate op signer, got %v", err)
	}
}

// TestPhoenixLineageBroken: tamper with the old-pubkey field of
// the second record so it no longer matches the first record's
// new-pubkey. VerifyLineage MUST reject.
func TestPhoenixLineageBroken(t *testing.T) {
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	h1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h3Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	wits := makeWitnesses(t, 5)

	birth, _ := SealRequest("service-S", h1Pub, nil, opPriv, 10*time.Millisecond)
	att0 := attestAll(t, birth, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	r0, _ := Execute(birth, att0, 3, birth.RequestedAtMs+birth.CoolDownMs+1)

	rebirth, _ := SealRequest("service-S", h2Pub, h1Pub, opPriv, 10*time.Millisecond)
	att1 := attestAll(t, rebirth, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	r1, _ := Execute(rebirth, att1, 3, rebirth.RequestedAtMs+rebirth.CoolDownMs+1)

	// Inject a record that doesn't chain — claims to rebirth
	// from H3 → H4, but our lineage ended at H2.
	h4Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	spliced, _ := SealRequest("service-S", h4Pub, h3Pub, opPriv, 10*time.Millisecond)
	att2 := attestAll(t, spliced, wits, 3, []ed25519.PublicKey{opPub}, 10*time.Millisecond)
	r2, _ := Execute(spliced, att2, 3, spliced.RequestedAtMs+spliced.CoolDownMs+1)

	if err := VerifyLineage([]LineageRecord{*r0, *r1, *r2}, [][]byte{opPub}, 1, 3); !errors.Is(err, ErrRebirth) {
		t.Fatalf("expected lineage-broken error, got %v", err)
	}
}

// ---- helpers ---------------------------------------------------

type testWitness struct {
	index int
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
}

func makeWitnesses(t *testing.T, n int) []testWitness {
	t.Helper()
	out := make([]testWitness, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("witness keygen[%d]: %v", i, err)
		}
		out[i] = testWitness{index: i, pub: pub, priv: priv}
	}
	return out
}

func attestAll(t *testing.T, req *Request, wits []testWitness, howMany int, pinnedOps []ed25519.PublicKey, minCool time.Duration) []Attestation {
	t.Helper()
	// Pick observation time after the cool-down elapses.
	observedAt := req.RequestedAtMs + req.CoolDownMs + 1
	// Convert pinned operators to [][]byte.
	pinned := make([][]byte, len(pinnedOps))
	for i, p := range pinnedOps {
		pinned[i] = p
	}
	out := make([]Attestation, howMany)
	for i := 0; i < howMany; i++ {
		a, err := Attest(req, pinned, 1, wits[i].index, wits[i].priv, observedAt, minCool)
		if err != nil {
			t.Fatalf("attest[%d]: %v", i, err)
		}
		out[i] = *a
	}
	return out
}
