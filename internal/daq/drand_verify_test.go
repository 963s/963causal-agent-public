package daq

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestVerifyDrandBeaconPinned checks VerifyDrandBeacon against a
// hardcoded golden triple captured by curl:
//
//   $ curl https://api.drand.sh/52db9ba.../public/27883886
//   {"round": 27883886,
//    "randomness":"80a2d61d...",
//    "signature":"b18cc83500e2dc4a...c5dbdb8218fbe99c aa620f9bd99db243b82dda2993b4df2c"}
//
// Hardcoding one round keeps this test hermetic; the online sibling
// (TestVerifyDrandBeaconLive) exercises the same path against
// whatever round is fresh when CI runs — but is skipped when
// network access is unavailable (e.g. sandboxed dev boxes).
func TestVerifyDrandBeaconPinned(t *testing.T) {
	const (
		round = uint64(27883886)
		sigHex = "b18cc83500e2dc4aa0b9187841f26cb7b84eacb809331ff3c5dbdb8218fbe99caa620f9bd99db243b82dda2993b4df2c"
	)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sig hex: %v", err)
	}
	pub := ExpectedChainPubkey()

	if err := VerifyDrandBeacon(round, sig, pub); err != nil {
		t.Fatalf("pinned beacon must verify: %v", err)
	}

	// Tampered signature: flip the high-order byte so the point is
	// either invalid on the subgroup or (more often) parses but
	// verifies against a different message.
	sig[0] ^= 0x01
	if err := VerifyDrandBeacon(round, sig, pub); err == nil {
		t.Fatal("tampered sig unexpectedly verified")
	}
	sig[0] ^= 0x01

	// Wrong round: valid sig vs. the wrong message → fail.
	if err := VerifyDrandBeacon(round+1, sig, pub); err == nil {
		t.Fatal("wrong-round verify unexpectedly succeeded")
	}
}

// TestVerifyDrandBeaconLive fetches a fresh round and checks it. Set
// CAUSAL_963_DAQ_NETWORK_TEST=1 to enable; default skip keeps the core
// test suite hermetic.
func TestVerifyDrandBeaconLive(t *testing.T) {
	if os.Getenv("CAUSAL_963_DAQ_NETWORK_TEST") != "1" {
		t.Skip("set CAUSAL_963_DAQ_NETWORK_TEST=1 to reach api.drand.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cli := NewDrandClient(DefaultDrandChain, nil)
	r, err := cli.FetchLatest(ctx)
	if err != nil {
		t.Fatalf("fetch latest: %v", err)
	}
	if err := VerifyDrandBeacon(r.Round, r.Signature, ExpectedChainPubkey()); err != nil {
		t.Fatalf("live beacon must verify: %v", err)
	}
	t.Logf("live fastnet round %d verified", r.Round)
}
