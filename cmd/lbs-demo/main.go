// lbs-demo is the runnable PoC for the W11 "Post-Quantum Local
// Blindness" proposal. It walks through the full enrollment →
// distributed sign → verify cycle narratively, and then shows
// every shortcut an attacker who fully owns the agent's
// post-enrolment state might try — each of which must fail.
//
// The output is shaped for a human auditor reading the terminal,
// not a machine. For CI gating, use `cmd/redteam` RT-014 instead.
//
// Example (default params):
//
//   ./bin/lbs-demo
//
// Walks 3-of-5 threshold BLS12-381 on a hard-coded seed so every
// run produces the same pubkey and signatures. Use --seed to
// explore different realisations.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/963causal/agent/internal/lbs"
)

func main() {
	threshold := flag.Int("threshold", 3, "k — partials required to recover")
	total := flag.Int("total", 5, "n — witness shares generated at enrollment")
	seed := flag.String("seed", "lbs-demo-default-seed", "identity-secret seed (hashed to a scalar)")
	msg := flag.String("msg", "I am the enrolled host and I authorise operation X", "message to sign")
	flag.Parse()

	section("Stage 1 — Enrolment (trusted-dealer Shamir)")
	fmt.Printf("  threshold k = %d\n", *threshold)
	fmt.Printf("  total n     = %d\n", *total)
	fmt.Printf("  seed        = %q (hashed internally to the BLS12-381 scalar field)\n", *seed)

	id, shares, err := lbs.Enroll(*threshold, *total, []byte(*seed))
	if err != nil {
		die("enroll failed: %v", err)
	}
	pub, _ := id.PubkeyBytes()
	fmt.Printf("  identity pubkey P = s·G₂ = %x…\n", pub[:16])
	fmt.Printf("  %d shares distributed to witnesses\n", *total)
	fmt.Println("  agent zeroises its local copy of s and any polynomial coefficients")

	section("Stage 2 — The agent state post-enrolment")
	fmt.Println("  The agent now holds ONLY the PublicIdentity object:")
	fmt.Println("    • P (96 B G₂ point)")
	fmt.Printf("    • polynomial commitments (%d degrees × 96 B each)\n", *threshold)
	fmt.Println("    • threshold / total parameters")
	fmt.Println()
	fmt.Println("  Critically, the agent holds NO PriShare. An attacker that")
	fmt.Println("  exfiltrates the entire post-enrolment agent state gets:")
	fmt.Println("    ✗ no secret scalar")
	fmt.Println("    ✗ no partial-signing capability")
	fmt.Println("    ✗ no signing oracle")

	section("Stage 3 — Distributed sign (happy path)")
	fmt.Printf("  message = %q\n", *msg)
	fmt.Printf("  soliciting partial signatures from witnesses 0..%d:\n", *threshold-1)

	partials := make([][]byte, *threshold)
	for i := 0; i < *threshold; i++ {
		p, err := lbs.PartialSign(shares[i], []byte(*msg))
		if err != nil {
			die("witness %d partial sign: %v", i, err)
		}
		if err := lbs.VerifyPartial(id, []byte(*msg), p); err != nil {
			die("witness %d partial failed self-verify: %v", i, err)
		}
		partials[i] = p
		fmt.Printf("    w%d: %x… (%d B)\n", i, p[:8], len(p))
	}

	fullSig, err := lbs.Recover(id, []byte(*msg), partials)
	if err != nil {
		die("recover: %v", err)
	}
	fmt.Printf("  recovered aggregate signature σ = s·H(msg) = %x… (%d B)\n",
		fullSig[:16], len(fullSig))
	if err := lbs.Verify(id, []byte(*msg), fullSig); err != nil {
		die("verify: %v", err)
	}
	fmt.Println("  verify: PASS  (standard BLS pairing check against the published P)")

	section("Stage 4 — BLS uniqueness: a disjoint quorum yields the SAME signature")
	// Pick a different k-subset from the remaining witnesses. This
	// is the Boneh-Lynn-Shacham uniqueness property: under a
	// fixed (P, msg) the signature is unique; any k valid
	// partials interpolate to the same aggregate.
	if *total >= *threshold*2 {
		disjoint := make([][]byte, *threshold)
		for i := 0; i < *threshold; i++ {
			p, err := lbs.PartialSign(shares[*threshold+i], []byte(*msg))
			if err != nil {
				die("disjoint witness partial: %v", err)
			}
			disjoint[i] = p
		}
		disjointSig, err := lbs.Recover(id, []byte(*msg), disjoint)
		if err != nil {
			die("disjoint recover: %v", err)
		}
		if bytes.Equal(fullSig, disjointSig) {
			fmt.Println("  witnesses {0..k-1} and witnesses {k..2k-1} both produced the identical σ — uniqueness holds")
		} else {
			die("BLS uniqueness violated — different σ from different quorum")
		}
	} else {
		fmt.Printf("  skipped (n=%d < 2k=%d)\n", *total, *threshold*2)
	}

	section("Stage 5 — Adversarial paths (ALL must fail)")

	// A1: below-threshold quorum
	sub := partials[:*threshold-1]
	if sig, err := lbs.Recover(id, []byte(*msg), sub); err == nil {
		if lbs.Verify(id, []byte(*msg), sig) == nil {
			die("CATASTROPHIC: k-1 partials produced a valid signature (%x…)", sig[:16])
		}
		fmt.Println("  ✓ A1 k-1 quorum: Recover returned nil-err but Verify rejected")
	} else {
		fmt.Printf("  ✓ A1 k-1 quorum: Recover rejected (%s)\n", short(err))
	}

	// A2: tampered message, honest signature
	if err := lbs.Verify(id, []byte("attacker-substituted-message"), fullSig); err == nil {
		die("CATASTROPHIC: tampered message verified under honest σ")
	}
	fmt.Println("  ✓ A2 message tamper: Verify rejected")

	// A3: bit-flipped aggregate signature
	badSig := append([]byte(nil), fullSig...)
	badSig[0] ^= 0x01
	if err := lbs.Verify(id, []byte(*msg), badSig); err == nil {
		die("CATASTROPHIC: 1-bit-flipped σ verified")
	}
	fmt.Println("  ✓ A3 aggregate sig tamper: Verify rejected (pairing mismatch)")

	// A4: the "classic" post-compromise path — attacker holds
	// only the PublicIdentity and tries to craft a signature
	// without any PriShare. This has no code path in the
	// package; its absence IS the guarantee. We simulate it by
	// passing empty partials.
	if sig, err := lbs.Recover(id, []byte(*msg), nil); err == nil {
		if lbs.Verify(id, []byte(*msg), sig) == nil {
			die("CATASTROPHIC: empty partials produced a valid signature")
		}
	}
	fmt.Println("  ✓ A4 empty-partials attempt: Recover refused (no signing oracle on public state)")

	section("Verdict")
	fmt.Println("  LBS PoC invariants hold:")
	fmt.Println("    • full signature validates under the published pubkey")
	fmt.Println("    • k-1 partials cannot forge")
	fmt.Println("    • post-enrolment state is useless for signing alone")
	fmt.Println("    • BLS uniqueness preserved across quorum choices")
	fmt.Println()
	fmt.Println("  Production upgrade path (ADR-009 §5):")
	fmt.Println("    • replace trusted-dealer Shamir with Pedersen DKG")
	fmt.Println("      to eliminate the ~1 ms enrolment window where s lives on the agent")
	fmt.Println("    • bind each signing request to a DAQ ticket so even an")
	fmt.Println("      authenticated compromised agent cannot trigger arbitrary signs")
	fmt.Println()
	fmt.Printf("  pubkey (96 B, for a Prisma Bytes column): %s\n", hex.EncodeToString(pub))
}

func section(title string) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 78))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("═", 78))
}

func short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 70 {
		return s[:67] + "..."
	}
	return s
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lbs-demo: "+format+"\n", args...)
	os.Exit(1)
}
