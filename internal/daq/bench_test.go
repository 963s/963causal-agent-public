package daq

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Benchmarks answer the "observer effect" critique with numbers.
// Each benchmark prints ns/op + B/op + allocs/op so an operator
// can compute the CPU cost of running 963causal alongside a
// production workload.

// BenchmarkBDNSign measures one witness partial-sign (G1 hash-to-
// curve + scalar multiplication). This is what each of the 5
// witnesses does on every DAQ request. Scales linearly with
// request rate.
func BenchmarkBDNSign(b *testing.B) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for BDN sign")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(priv, msg)
	}
}

// BenchmarkBDNVerifyAggregate is what the verifier does once per
// DAQ ticket: aggregate the k pubkeys + pair against the 48-byte
// sig. O(k) pairings under the hood.
func BenchmarkBDNVerifyAggregate(b *testing.B) {
	roster, privs := makeRosterBench(b, 5)
	msg := []byte("benchmark message")
	sigs := [][]byte{
		mustSignBench(b, privs[0], msg),
		mustSignBench(b, privs[1], msg),
		mustSignBench(b, privs[2], msg),
	}
	agg, err := AggregateSigs(roster, []int{0, 1, 2}, sigs)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = VerifyAggregate(roster, agg.Mask, agg.Signature, msg, 3)
	}
}

// BenchmarkDrandVerify measures ADR-005's pinned BLS verify of a
// drand beacon. Runs once per signing attempt on every witness;
// the cost budget here sets the throughput ceiling for the whole
// DAQ.
func BenchmarkDrandVerify(b *testing.B) {
	// Reuse a golden round captured at ADR-005 time; the test
	// isn't ordering-sensitive.
	round := uint64(27883886)
	sigHex := "b18cc83500e2dc4aa0b9187841f26cb7b84eacb809331ff3c5dbdb8218fbe99caa620f9bd99db243b82dda2993b4df2c"
	sig := make([]byte, 48)
	for i := 0; i < 48; i++ {
		hi := hexVal(sigHex[2*i])
		lo := hexVal(sigHex[2*i+1])
		sig[i] = byte(hi<<4 | lo)
	}
	pub := ExpectedChainPubkey()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = VerifyDrandBeacon(round, sig, pub)
	}
}

// BenchmarkEd25519Sign is the baseline every one of the 14 test
// cases uses for the agent's Ed25519 identity. Included so an
// operator comparing "BDN vs Ed25519 per signature" has both
// numbers on the same CPU.
func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message for Ed25519")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}

// -----------------------------------------------------------------
// Helpers (duplicated from bls_test.go because benchmark helpers
// cannot close over *testing.T).

func makeRosterBench(b *testing.B, n int) ([]*PublicKey, []*PrivateKey) {
	b.Helper()
	privs := make([]*PrivateKey, n)
	pubs := make([]*PublicKey, n)
	for i := 0; i < n; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("keygen[%d]: %v", i, err)
		}
		privs[i] = priv
		pubs[i] = pub
	}
	return pubs, privs
}

func mustSignBench(b *testing.B, priv *PrivateKey, msg []byte) []byte {
	b.Helper()
	sig, err := Sign(priv, msg)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	return sig
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}
