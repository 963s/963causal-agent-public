package daq

import (
	"bytes"
	"testing"
)

// TestRoundTripIndividual exercises the simplest case: one witness,
// one signature. Guards against regressions in the BLS wrapper where
// Sign / Verify lose alignment on the pairing DST or the compression
// format.
func TestRoundTripIndividual(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("the ordinary hero of the day")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig size = %d, want %d", len(sig), SignatureSize)
	}
	if err := VerifyIndividual(pub, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Tampered message must not verify.
	if err := VerifyIndividual(pub, []byte("tampered"), sig); err == nil {
		t.Fatal("tampered verify unexpectedly succeeded")
	}
}

// TestAggregate3of5 builds a full 5-witness roster and checks the
// core DAQ guarantee: any 3 of them can produce an aggregate that
// verifies under the aggregated public-key derivation.
func TestAggregate3of5(t *testing.T) {
	roster, privs := makeRoster(t, 5)
	msg := []byte("quorum msg for 3-of-5 test")

	sigs := make([][]byte, 3)
	for i, idx := range []int{0, 2, 4} {
		s, err := Sign(privs[idx], msg)
		if err != nil {
			t.Fatalf("sign w=%d: %v", idx, err)
		}
		sigs[i] = s
	}
	agg, err := AggregateSigs(roster, []int{0, 2, 4}, sigs)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.Count != 3 {
		t.Fatalf("count = %d, want 3", agg.Count)
	}
	if len(agg.Signature) != SignatureSize {
		t.Fatalf("aggregated sig size = %d, want %d", len(agg.Signature), SignatureSize)
	}
	if err := VerifyAggregate(roster, agg.Mask, agg.Signature, msg, 3); err != nil {
		t.Fatalf("aggregate verify: %v", err)
	}
	// Below-threshold must be rejected.
	if err := VerifyAggregate(roster, agg.Mask, agg.Signature, msg, 4); err == nil {
		t.Fatal("k=4 verify on k=3 aggregate unexpectedly succeeded")
	}
	// Tampered message must be rejected.
	if err := VerifyAggregate(roster, agg.Mask, agg.Signature, []byte("evil"), 3); err == nil {
		t.Fatal("tampered message verify unexpectedly succeeded")
	}
}

// TestAggregateWrongSignerRejected confirms that an aggregate built
// from genuine signatures under the wrong bitmask fails verification.
// This is the "attacker swaps the bitmask to claim different witnesses
// signed" attack; BDN's coefficient term must catch it.
func TestAggregateWrongSignerRejected(t *testing.T) {
	roster, privs := makeRoster(t, 5)
	msg := []byte("quorum msg")

	sigs := make([][]byte, 3)
	for i, idx := range []int{0, 1, 2} {
		s, err := Sign(privs[idx], msg)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sigs[i] = s
	}
	agg, err := AggregateSigs(roster, []int{0, 1, 2}, sigs)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Swap mask to claim {3, 4, 0} instead of {0, 1, 2}.
	fakeIdx := []int{0, 3, 4}
	fakeRes, err := AggregateSigs(roster, fakeIdx, sigs)
	if err == nil {
		// Mask-swap at aggregation succeeds structurally; but the
		// aggregated sig will not verify because coefficients differ.
		if err := VerifyAggregate(roster, fakeRes.Mask, fakeRes.Signature, msg, 3); err == nil {
			t.Fatal("mask-swap verify unexpectedly succeeded")
		}
	}
	// Manually-forged mask: take the original aggregate sig but set
	// a different bit pattern claiming witness 3 signed too.
	forgedMask := append([]byte(nil), agg.Mask...)
	forgedMask[0] |= 1 << 3 // claim witness 3 as well
	if err := VerifyAggregate(roster, forgedMask, agg.Signature, msg, 3); err == nil {
		t.Fatal("forged mask (extra signer) verify unexpectedly succeeded")
	}
}

// TestPrivateKeyRoundTrip confirms MarshalBinary / UnmarshalPrivateKey
// preserves both the scalar and the derived pubkey.
func TestPrivateKeyRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	buf, err := priv.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	priv2, err := UnmarshalPrivateKey(buf)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pub2 := priv2.Public()
	pubA, _ := pub.MarshalBinary()
	pubB, _ := pub2.MarshalBinary()
	if !bytes.Equal(pubA, pubB) {
		t.Fatal("pub derived from unmarshalled priv differs")
	}

	// Signatures under the reconstructed key must still verify.
	msg := []byte("round-trip signing check")
	sig, err := Sign(priv2, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyIndividual(pub, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func makeRoster(t *testing.T, n int) ([]*PublicKey, []*PrivateKey) {
	t.Helper()
	privs := make([]*PrivateKey, n)
	pubs := make([]*PublicKey, n)
	for i := 0; i < n; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("keygen[%d]: %v", i, err)
		}
		privs[i] = priv
		pubs[i] = pub
	}
	return pubs, privs
}
