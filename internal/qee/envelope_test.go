package qee

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// TestEnvelopeSiliconFastPath: H₁ seals, H₁ opens. Happy path.
// Asserts the data round-trips bit-exact.
func TestEnvelopeSiliconFastPath(t *testing.T) {
	siliconPub, siliconPriv := genBoxKeys(t)
	_, witnesses := genWitnesses(t, 5)

	plaintext := []byte("the secret payload H1 encrypts at rest")
	env, err := Seal(plaintext, siliconPub, witnesses, 3)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenSilicon(env, siliconPub, siliconPriv)
	if err != nil {
		t.Fatalf("open silicon: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch")
	}
}

// TestEnvelopeRecoveryPath: H₁ has "died" — the test throws
// away siliconPriv. We reconstruct via ≥ k witness shares and
// ReSeal to a new silicon identity. The NEW host then opens via
// its own siliconPriv. No master key anywhere.
func TestEnvelopeRecoveryPath(t *testing.T) {
	h1Pub, _ /* h1Priv thrown away */ := genBoxKeys(t)
	witPrivs, witnesses := genWitnesses(t, 5)
	plaintext := []byte("the ciphertext sealed on H1 that H2 must recover")
	env, err := Seal(plaintext, h1Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// 3 witnesses each decrypt their Shamir share. We pick
	// witnesses 0, 2, 4 to exercise non-contiguous indexes.
	wIdx := []int{0, 2, 4}
	shares := make([]Share, len(wIdx))
	for i, idx := range wIdx {
		// Locate the WitnessShare whose WitnessIndex matches
		// the roster slot.
		var found *WitnessShare
		for j := range env.WitnessShares {
			if env.WitnessShares[j].WitnessIndex == witnesses[idx].Index {
				found = &env.WitnessShares[j]
				break
			}
		}
		if found == nil {
			t.Fatalf("witness share for index %d not found", idx)
		}
		share, err := WitnessUnboxShare(*found, witnesses[idx].Pubkey, witPrivs[idx])
		if err != nil {
			t.Fatalf("unbox witness[%d]: %v", idx, err)
		}
		shares[i] = share
	}

	// Combine to reconstruct DEK.
	dek, err := RecoverDEK(env, shares)
	if err != nil {
		t.Fatalf("recover DEK: %v", err)
	}
	if len(dek) != DataKeyBytes {
		t.Fatalf("DEK length %d, want %d", len(dek), DataKeyBytes)
	}

	// Rebind to a fresh silicon identity (H₂).
	h2Pub, h2Priv := genBoxKeys(t)
	newEnv, err := ReSeal(env, dek, h2Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	// Now H₂ opens directly via its OWN silicon.
	got, err := OpenSilicon(newEnv, h2Pub, h2Priv)
	if err != nil {
		t.Fatalf("open silicon on new host: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovery round trip mismatch")
	}
}

// TestEnvelopeBelowThresholdRejected: k-1 witness shares cannot
// reconstruct the DEK. This is the core "no master key"
// property — an adversary with DB + operator key + k-1 witness
// keys still cannot open.
func TestEnvelopeBelowThresholdRejected(t *testing.T) {
	h1Pub, _ := genBoxKeys(t)
	witPrivs, witnesses := genWitnesses(t, 5)
	env, err := Seal([]byte("secret"), h1Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Only 2 witness shares (k = 3).
	shares := make([]Share, 2)
	for i := 0; i < 2; i++ {
		share, err := WitnessUnboxShare(env.WitnessShares[i], witnesses[i].Pubkey, witPrivs[i])
		if err != nil {
			t.Fatalf("unbox: %v", err)
		}
		shares[i] = share
	}
	if _, err := RecoverDEK(env, shares); err == nil {
		t.Fatal("RecoverDEK with k-1 shares unexpectedly succeeded")
	}
}

// TestEnvelopeSingleWitnessCompromiseInsufficient: an attacker
// who compromises only ONE witness sees nothing useful. Their
// share alone reconstructs a random byte string, not the DEK;
// and that random string cannot decrypt the AEAD.
func TestEnvelopeSingleWitnessCompromiseInsufficient(t *testing.T) {
	h1Pub, _ := genBoxKeys(t)
	witPrivs, witnesses := genWitnesses(t, 5)
	env, err := Seal([]byte("secret"), h1Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Attacker unboxes witness 0's share. They know ONE
	// (index, share_bytes) pair.
	share, err := WitnessUnboxShare(env.WitnessShares[0], witnesses[0].Pubkey, witPrivs[0])
	if err != nil {
		t.Fatalf("unbox: %v", err)
	}
	// With only k=1 threshold they can "combine" (trivially a
	// single share is "polynomial degree 0"). But that
	// reconstructs as if threshold were 1, producing a completely
	// different DEK. The AEAD should refuse to open with that.
	reconstructed, err := Combine([]Share{share}, 1)
	if err != nil {
		t.Fatalf("single-share combine: %v", err)
	}
	// The resulting "DEK" cannot open the AEAD because it is
	// the y-intercept of a degree-0 polynomial that happens to
	// pass through (1, share_bytes), not the real degree-2
	// polynomial's y-intercept.
	var fakeDEK [DataKeyBytes]byte
	copy(fakeDEK[:], reconstructed)
	// Try to open — must fail.
	// We use the SAME opening path ReSeal would have; reusing
	// OpenSilicon isn't the clean match here, so we go direct.
	// If the attacker tried to ReSeal with this fake DEK and
	// then read, the data-AEAD would still fail because the
	// data was sealed under the REAL DEK, not the fake one.
	h2Pub, h2Priv := genBoxKeys(t)
	badEnv, err := ReSeal(env, fakeDEK[:], h2Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("reseal with fake DEK should structurally succeed: %v", err)
	}
	if _, err := OpenSilicon(badEnv, h2Pub, h2Priv); err == nil {
		t.Fatal("AEAD open unexpectedly succeeded with single-share-derived fake DEK")
	}
}

// TestEnvelopeADBindsThreshold: an attacker who edits the
// stored threshold (e.g. to lower it from 3 to 1 so they can
// unlock with fewer shares) trips the AEAD's authenticated-
// data check.
func TestEnvelopeADBindsThreshold(t *testing.T) {
	h1Pub, h1Priv := genBoxKeys(t)
	_, witnesses := genWitnesses(t, 5)
	env, err := Seal([]byte("original"), h1Pub, witnesses, 3)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Attacker lowers threshold to 1.
	env.Threshold = 1
	if _, err := OpenSilicon(env, h1Pub, h1Priv); err == nil {
		t.Fatal("AEAD open accepted tampered threshold")
	}
}

// ---------------------------------------------------------------------
// Helpers.

func genBoxKeys(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey: %v", err)
	}
	return *pub, *priv
}

func genWitnesses(t *testing.T, n int) ([][32]byte, []WitnessPubkey) {
	t.Helper()
	privs := make([][32]byte, n)
	pubs := make([]WitnessPubkey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("witness[%d] keygen: %v", i, err)
		}
		privs[i] = *priv
		pubs[i] = WitnessPubkey{Index: i, Pubkey: *pub}
	}
	return privs, pubs
}
