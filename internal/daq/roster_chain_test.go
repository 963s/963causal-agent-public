package daq

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

var _ = rand.Reader // shared across tests that mint fresh ed25519 keys

// TestRosterChainHappyPath exercises the positive flow: genesis
// ceremony with 3 signers, then two legitimate transitions, then
// chain verify succeeds end-to-end.
func TestRosterChainHappyPath(t *testing.T) {
	genesisWitnesses, genesisPrivs := makeWitnesses(t, 5)
	ceremonySigs, ceremonyPrivs := makeCeremony(t, 3)
	genesis, err := SealGenesis(genesisWitnesses, 3, 1000, ceremonySigs, ceremonyPrivs)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}

	// Transition 1: keep the same witness set but bump the
	// threshold to 4 (operational tightening).
	epoch1, err := SealTransition(genesis, genesisWitnesses, 4, 2000,
		[]int{0, 1, 2}, []ed25519.PrivateKey{genesisPrivs[0], genesisPrivs[1], genesisPrivs[2]})
	if err != nil {
		t.Fatalf("transition 1: %v", err)
	}

	// Transition 2: rotate to an entirely new 5-witness set,
	// signed by 4 of epoch1's witnesses (meeting the new k=4).
	nextWitnesses, _ := makeWitnesses(t, 5)
	_, err = SealTransition(epoch1, nextWitnesses, 3, 3000,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genesisPrivs[0], genesisPrivs[1], genesisPrivs[2], genesisPrivs[3]})
	if err != nil {
		t.Fatalf("transition 2: %v", err)
	}

	chain := &RosterChain{Epochs: []Epoch{*genesis, *epoch1}}
	trusted := ceremonyPubkeys(ceremonySigs)
	latest, err := VerifyChain(chain, trusted)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if latest.EpochNum != 1 {
		t.Fatalf("latest.EpochNum = %d, want 1", latest.EpochNum)
	}
}

// TestRosterChainRejectsUntrustedGenesisSigner is the core
// "attacker replaces roster in DB" defence: even if the attacker
// can write whatever bytes they want to the chain, the genesis
// ceremony signers are PINNED (their pubkeys hardcoded in BSL
// ADR-011). An attacker who can't sign as one of them cannot
// fabricate a fresh genesis.
func TestRosterChainRejectsUntrustedGenesisSigner(t *testing.T) {
	genWit, _ := makeWitnesses(t, 3)
	ceremonySigs, ceremonyPrivs := makeCeremony(t, 2)
	genesis, err := SealGenesis(genWit, 2, 0, ceremonySigs, ceremonyPrivs)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	chain := &RosterChain{Epochs: []Epoch{*genesis}}

	// Attacker's "pinned" set: not including any real ceremony
	// signer. The chain should refuse.
	attackerPinned := [][]byte{make([]byte, ed25519.PublicKeySize)}
	if _, err := VerifyChain(chain, attackerPinned); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken with untrusted pin set, got %v", err)
	}
}

// TestRosterChainRejectsForgedTransitionSig models the direct DB
// attack: attacker swaps in a new Epoch whose transition sigs
// are random bytes. VerifyChain must refuse at the signature
// check.
func TestRosterChainRejectsForgedTransitionSig(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)

	epoch1, _ := SealTransition(genesis, genWit, 3, 1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]})
	// Tamper: overwrite the first signature with zeros.
	for i := 0; i < ed25519.SignatureSize; i++ {
		epoch1.TransitionSig[i] = 0
	}
	chain := &RosterChain{Epochs: []Epoch{*genesis, *epoch1}}
	if _, err := VerifyChain(chain, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on forged transition sig, got %v", err)
	}
}

// TestRosterChainRejectsBelowThresholdTransition models the
// "attacker has ONE insider at the current epoch" case. One sig
// is a genuine Ed25519 sig from one real witness, but the
// transition threshold is 3. One genuine + two garbage should
// fail the verify (garbage doesn't match witnesses, plus total
// count of GENUINE sigs is below threshold anyway).
func TestRosterChainRejectsBelowThresholdTransition(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)

	// Seal WITH threshold honoured — this gives us a valid blob
	// to mutate below.
	epoch1, _ := SealTransition(genesis, genWit, 3, 1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]})
	// Now mutate: pretend only one signer (below threshold 3).
	epoch1.TransitionSigners = []int{0}
	epoch1.TransitionSig = epoch1.TransitionSig[:ed25519.SignatureSize]
	// Re-hash because we changed canonical bytes.
	epoch1.Hash = epoch1.hash()
	chain := &RosterChain{Epochs: []Epoch{*genesis, *epoch1}}
	if _, err := VerifyChain(chain, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on below-threshold transition, got %v", err)
	}
}

// TestRosterChainRejectsSplicedEpoch models the hash-chain
// integrity property: an attacker inserts an extra epoch in the
// middle and renumbers the rest. PrevHash mismatches immediately.
func TestRosterChainRejectsSplicedEpoch(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	epoch1, _ := SealTransition(genesis, genWit, 3, 1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]})

	// Splice a fabricated epoch between genesis and epoch1.
	fake := *epoch1
	fake.EpochNum = 1
	fake.PrevHash = nil // pretend it chains off nowhere
	fake.Hash = fake.hash()

	spliced := &RosterChain{Epochs: []Epoch{*genesis, fake, *epoch1}}
	// epoch1's .EpochNum will no longer match its position; chain broken.
	if _, err := VerifyChain(spliced, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on spliced epoch, got %v", err)
	}
}

// TestRosterChainRejectsReusedGenesisSigner tests the
// duplicate-detection defence: an attacker who controls ONE
// ceremony signer tries to count it twice. VerifyChain catches
// duplicate SignerPubkey entries.
func TestRosterChainRejectsReusedGenesisSigner(t *testing.T) {
	genWit, _ := makeWitnesses(t, 3)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 2, 0, cerSigs, cerPrivs)
	// Attacker duplicates the first ceremony sig and publishes
	// the resulting "2-of-2" genesis.
	genesis.GenesisCeremony = []CeremonySig{
		genesis.GenesisCeremony[0],
		genesis.GenesisCeremony[0], // duplicate
	}
	chain := &RosterChain{Epochs: []Epoch{*genesis}}
	if _, err := VerifyChain(chain, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on duplicate ceremony signer, got %v", err)
	}
}

// TestRosterChainEmergencyRecoveryHappyPath covers the
// "permanent quorum loss" failure mode: the genesis ceremony
// signers are gone (deceased / keys destroyed / org exited)
// and the normal transition path is blocked. Emergency
// recovery with 4-of-5 current witnesses + an externally-pinned
// announcement key must succeed after the 24 h waiting period.
func TestRosterChainEmergencyRecoveryHappyPath(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)

	// Announcement key is an EXTERNALLY-PINNED authority
	// separate from witnesses and the ceremony — in production
	// typically the company's legal principal.
	annPub, annPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Emergency: 4 of 5 current witnesses co-sign + announcement
	// after a 24h+1s waiting period.
	const waitMs int64 = 24 * 60 * 60 * 1000
	declaredAt := int64(0)
	activatedAt := waitMs + 1000
	newWit, _ := makeWitnesses(t, 5)
	emergency, err := SealEmergencyTransition(genesis, newWit, 3, activatedAt,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2], genPrivs[3]},
		EmergencyParams{
			Declaration:     "ceremony signers unreachable for 90 days",
			DeclaredAtMs:    declaredAt,
			WaitingPeriodMs: waitMs,
		},
		annPriv)
	if err != nil {
		t.Fatalf("seal emergency: %v", err)
	}
	_ = annPub // captured inside emergency.AnnouncementPubkey

	chain := &RosterChain{Epochs: []Epoch{*genesis, *emergency}}
	if _, err := VerifyChain(chain, ceremonyPubkeys(cerSigs)); err != nil {
		t.Fatalf("emergency chain should verify: %v", err)
	}
}

// TestRosterChainEmergencyBelowSuperMajority rejects an attacker
// who has compromised only k witnesses and tries to invoke
// emergency as a DOWNGRADE to bypass the 4-of-5 super-majority.
func TestRosterChainEmergencyBelowSuperMajority(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	_, annPriv, _ := ed25519.GenerateKey(rand.Reader)

	const waitMs int64 = 24 * 60 * 60 * 1000
	_, err := SealEmergencyTransition(genesis, genWit, 3, waitMs+1000,
		[]int{0, 1, 2}, // ← only 3 signers, below 4-of-5
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]},
		EmergencyParams{Declaration: "evil", DeclaredAtMs: 0, WaitingPeriodMs: waitMs},
		annPriv)
	if err == nil {
		t.Fatal("expected emergency below super-majority to fail at Seal")
	}
}

// TestRosterChainEmergencyShortWaitingPeriod rejects an attempt
// to fast-track emergency recovery by setting an impossibly
// short waiting period.
func TestRosterChainEmergencyShortWaitingPeriod(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	_, annPriv, _ := ed25519.GenerateKey(rand.Reader)

	_, err := SealEmergencyTransition(genesis, genWit, 3, 3600*1000,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2], genPrivs[3]},
		EmergencyParams{Declaration: "rush", DeclaredAtMs: 0, WaitingPeriodMs: 3600 * 1000}, // 1h < 24h
		annPriv)
	if err == nil {
		t.Fatal("expected sub-24h waiting period to fail at Seal")
	}
}

// TestRosterChainEmergencyForgedAnnouncement catches an attacker
// who has compromised the super-majority of witnesses but does
// NOT have the announcement key. They attach a bogus sig.
func TestRosterChainEmergencyForgedAnnouncement(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	_, annPriv, _ := ed25519.GenerateKey(rand.Reader)

	const waitMs int64 = 24 * 60 * 60 * 1000
	emergency, err := SealEmergencyTransition(genesis, genWit, 3, waitMs+1000,
		[]int{0, 1, 2, 3},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2], genPrivs[3]},
		EmergencyParams{Declaration: "legit", DeclaredAtMs: 0, WaitingPeriodMs: waitMs},
		annPriv)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Tamper: flip one byte of the announcement signature.
	emergency.Emergency.AnnouncementSig[0] ^= 0x01
	// Re-hash because Canonical() includes AnnouncementPubkey
	// (not the sig itself — we keep the hash valid so VerifyChain
	// progresses past the hash-match step and rejects specifically
	// on the announcement signature).
	emergency.Hash = emergency.hash()

	chain := &RosterChain{Epochs: []Epoch{*genesis, *emergency}}
	if _, err := VerifyChain(chain, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on forged announcement, got %v", err)
	}
}

// TestRosterChainRejectsRollback models the "attacker serves an
// older epoch that they still have valid signatures for".
// VerifyChain walks the chain in order; serving epoch 0 alone
// after epoch 1 was legitimately activated is detected at the
// caller level by a freshness monotone-counter check. Here we
// confirm the chain library rejects a chain that simply omits
// intermediate epochs: epoch 2 with PrevHash = epoch 0's hash
// fails because the hash chain breaks.
func TestRosterChainRejectsRollback(t *testing.T) {
	genWit, genPrivs := makeWitnesses(t, 5)
	cerSigs, cerPrivs := makeCeremony(t, 2)
	genesis, _ := SealGenesis(genWit, 3, 0, cerSigs, cerPrivs)
	epoch1, _ := SealTransition(genesis, genWit, 3, 1000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]})
	epoch2, _ := SealTransition(epoch1, genWit, 3, 2000,
		[]int{0, 1, 2},
		[]ed25519.PrivateKey{genPrivs[0], genPrivs[1], genPrivs[2]})

	// Attacker serves [genesis, epoch2] — skipping epoch1 to
	// shorten the chain. Epoch2's PrevHash points at epoch1's
	// hash, not genesis', so the link fails.
	truncated := &RosterChain{Epochs: []Epoch{*genesis, *epoch2}}
	if _, err := VerifyChain(truncated, ceremonyPubkeys(cerSigs)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken on rollback-skip, got %v", err)
	}
}

// -----------------------------------------------------------------

func makeWitnesses(t *testing.T, n int) ([]EpochWitness, []ed25519.PrivateKey) {
	t.Helper()
	ws := make([]EpochWitness, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen[%d]: %v", i, err)
		}
		ws[i] = EpochWitness{
			Index:  i,
			Label:  "w" + itoa(i),
			URL:    "http://localhost:" + itoa(17001+i),
			Pubkey: pub,
		}
		privs[i] = priv
	}
	return ws, privs
}

func makeCeremony(t *testing.T, n int) ([]CeremonySig, []ed25519.PrivateKey) {
	t.Helper()
	sigs := make([]CeremonySig, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ceremony keygen[%d]: %v", i, err)
		}
		sigs[i] = CeremonySig{SignerPubkey: pub, SignerLabel: "ceremony-" + itoa(i)}
		privs[i] = priv
	}
	return sigs, privs
}

func ceremonyPubkeys(sigs []CeremonySig) [][]byte {
	out := make([][]byte, len(sigs))
	for i, s := range sigs {
		out[i] = s.SignerPubkey
	}
	return out
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + itoa(i%10)
}
