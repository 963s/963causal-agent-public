package main

import (
	"errors"
	"fmt"

	"github.com/963causal/agent/internal/teb"
)

// -----------------------------------------------------------------
// RT-015 — TEB forced-ephemerality: pause-and-resume replay fails
// -----------------------------------------------------------------
// Hypothesis: an adversary with full snapshot access to the
// agent's address space AND the sealed TEB blob can resume the
// VM after the binding window has expired and still open the
// blob — thereby breaking the "secrets die after window" claim.
//
// Defence (W13 / ADR-010): the sealed blob binds to a specific
// (zone, window) tuple. Open() refuses before any cryptographic
// work whenever nowMs > windowStart + windowDuration. Additional
// protection: the AEAD authenticated-data block includes the
// window parameters, so an attacker who rewrites the blob header
// to extend validity trips the AEAD tag check.
//
// The harness checks both guards:
//
//   * pause-then-late-resume rejected with ErrOutOfWindow
//   * post-hoc header rewrite rejected with ErrOpen
//   * wrong-zone rejected with ErrWrongZone
//   * forged environment (attacker sampling a different signal)
//     rejected with ErrOpen
//
// Any path returning nil error on any attack fails RT-015.
//
// Explicit non-claims (per ADR-010):
//   * TEB does NOT protect against a hypervisor that can observe
//     AND replay the real environmental signal from the sealing
//     location. That failure mode remains in Ring -1 territory
//     and requires enclave composition; it is NOT part of this
//     test.
//   * Commodity-hardware sampling of ENF is not part of the PoC;
//     the signal model here is a deterministic mathematical
//     stand-in.
func (s *Suite) RT015_TEBForcedEphemerality() Finding {
	f := Finding{
		ID:         "RT-015",
		Name:       "TEB forced-ephemerality: pause-resume cannot re-open",
		Category:   "teb-replay",
		Hypothesis: "attacker snapshots the VM with the sealed blob, resumes after window expiry, opens the secret",
		Defence:    "TEB Open() enforces window bounds + AEAD-binds header into tag (ADR-010)",
		Expected:   "every post-window / wrong-zone / forged-env / tampered-header open rejected",
	}

	src := teb.NewDeterministicSignal()
	binding := []byte("rt-015-binding-secret")
	plaintext := []byte("TEB canary — should not be recoverable after window")

	blob, err := teb.Seal(src, binding, teb.ZoneID(100), 0, 10000, 100, plaintext)
	if err != nil {
		f.Verdict = Deferred
		f.Observed = "seal failed in harness setup"
		f.Evidence = err.Error()
		return f
	}

	// ---- Sanity: honest open inside the window works ----
	if got, err := teb.Open(src, binding, blob, teb.ZoneID(100), 5000); err != nil {
		f.Verdict = Deferred
		f.Observed = "honest open failed — harness bug, not a finding"
		f.Evidence = err.Error()
		return f
	} else if string(got) != string(plaintext) {
		f.Verdict = Deferred
		f.Observed = "honest open returned wrong plaintext"
		return f
	}

	// ---- Attack 1: resume 60 s after the 10 s window --------
	if _, err := teb.Open(src, binding, blob, teb.ZoneID(100), 70000); !errors.Is(err, teb.ErrOutOfWindow) {
		f.Verdict = Fail
		f.Observed = "pause-then-late-resume was not rejected with ErrOutOfWindow"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// ---- Attack 2: attacker carries the blob to another zone
	if _, err := teb.Open(src, binding, blob, teb.ZoneID(101), 5000); !errors.Is(err, teb.ErrWrongZone) {
		f.Verdict = Fail
		f.Observed = "wrong-zone open was not rejected"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// ---- Attack 3: attacker rewrites WindowStartMs post-hoc
	tampered := *blob
	tampered.WindowStartMs = 100_000
	if _, err := teb.Open(src, binding, &tampered, teb.ZoneID(100), 100_000+5000); !errors.Is(err, teb.ErrOpen) {
		f.Verdict = Fail
		f.Observed = "tampered WindowStartMs not rejected by AEAD"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// ---- Attack 4: attacker forges the environmental signal --
	forged := &teb.DeterministicSignal{AutocorrelationMs: 1500} // ≠ default 5000
	if _, err := teb.Open(forged, binding, blob, teb.ZoneID(100), 5000); !errors.Is(err, teb.ErrOpen) {
		f.Verdict = Fail
		f.Observed = "forged environment open was not rejected"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	// ---- Attack 5: wrong binding secret ---------------------
	if _, err := teb.Open(src, []byte("wrong-binding"), blob, teb.ZoneID(100), 5000); !errors.Is(err, teb.ErrOpen) {
		f.Verdict = Fail
		f.Observed = "wrong binding secret not rejected"
		f.Evidence = fmt.Sprintf("got %v", err)
		return f
	}

	f.Verdict = Pass
	f.Observed = "all 5 TEB adversarial paths rejected as specified"
	f.Evidence = "window, zone, header-tamper, env-forge, and binding-secret guards all active"
	return f
}
