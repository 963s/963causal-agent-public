package teb

import (
	"bytes"
	"errors"
	"testing"
)

// TestSealOpenHappyPath is the baseline: seal a secret in
// (zone=A, window=[1000, +30_000]ms), open it at t=15_000 (middle
// of the window). The plaintext must round-trip bit-exact.
func TestSealOpenHappyPath(t *testing.T) {
	src := NewDeterministicSignal()
	secret := []byte("long-lived-binding-secret-v1")
	plaintext := []byte("the location-bound payload")

	blob, err := Seal(src, secret, 42, 1000, 30000, 100, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	t.Logf("sealed: %s", blob.DebugString())

	got, err := Open(src, secret, blob, 42, 15000)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

// TestOpenAfterWindowExpiresFails is the core forced-ephemerality
// invariant: any `nowMs` past the window's upper bound MUST be
// rejected before any environmental re-sampling even happens.
// This path is deterministic and does not depend on the signal
// model; the check is a simple integer comparison.
func TestOpenAfterWindowExpiresFails(t *testing.T) {
	src := NewDeterministicSignal()
	blob, err := Seal(src, []byte("secret"), 7, 1000, 5000, 50, []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// 1 ms past window end.
	_, err = Open(src, []byte("secret"), blob, 7, 1000+5000+1)
	if !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("expected ErrOutOfWindow, got %v", err)
	}
	// Far future.
	_, err = Open(src, []byte("secret"), blob, 7, 1_000_000_000)
	if !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("expected ErrOutOfWindow on far-future open, got %v", err)
	}
}

// TestOpenWrongZoneFails confirms the zone-binding claim:
// sealing in zone A and opening in zone B fails at the
// parameter check, never exposing the AEAD tag to an attacker
// who might otherwise use partial decryption as an oracle.
func TestOpenWrongZoneFails(t *testing.T) {
	src := NewDeterministicSignal()
	blob, err := Seal(src, []byte("secret"), 10, 0, 10000, 100, []byte("zone-A secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(src, []byte("secret"), blob, 11, 5000); !errors.Is(err, ErrWrongZone) {
		t.Fatalf("expected ErrWrongZone, got %v", err)
	}
}

// TestOpenWithForgedEnvironmentFailsWhenSignalDiffers probes the
// deeper claim: even INSIDE the stated window and WITH the right
// zone parameter, an opener whose environmental signal does not
// actually match (modelled here by forcing a different
// autocorrelation constant, which changes every sample) fails to
// derive the key. This is the "stolen blob + wrong physical
// location" case — the blob travels, the environment does not.
func TestOpenWithForgedEnvironmentFailsWhenSignalDiffers(t *testing.T) {
	honestSrc := NewDeterministicSignal() // τ = 5 s
	adversarySrc := &DeterministicSignal{AutocorrelationMs: 2500}
	blob, err := Seal(honestSrc, []byte("secret"), 5, 0, 10000, 100, []byte("geo-bound"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Within the window, right zone, but the "environment" the
	// opener observes is fundamentally different.
	_, err = Open(adversarySrc, []byte("secret"), blob, 5, 5000)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on environment mismatch, got %v", err)
	}
}

// TestOpenAfterPauseAndResumeFails models the Ring -1 attack the
// memo specifically calls out: the VM is suspended at time
// T_0+50ms, snapshotted in its entirety, and resumed at some
// later wall clock > window end. At resume, the agent's monotonic
// clock has jumped; when it calls Open(nowMs = resumeTime) the
// window check refuses. The defence does NOT rely on the
// environmental sample here — it is a simple monotonic-time
// comparison — but it demonstrates the protocol correctly
// propagates the "time moved on" signal even through a full
// state snapshot and resume.
//
// The PoC limitation this test documents: if the hypervisor
// lies about the resume time (fakes clock = sealer's window),
// the code path this test exercises PASSES. That is exactly the
// "hypervisor-forged environment" case ADR-010 calls out as
// out-of-scope for TEB alone and requires enclave composition
// to address.
func TestOpenAfterPauseAndResumeFails(t *testing.T) {
	src := NewDeterministicSignal()
	blob, err := Seal(src, []byte("secret"), 3, 0, 30000, 500, []byte("resume-after-window"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Simulate: VM pauses at t=50 ms, gets snapshotted, resumes
	// at t=120000 ms (well past the 30-second window).
	_, err = Open(src, []byte("secret"), blob, 3, 120_000)
	if !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("expected ErrOutOfWindow on pause-then-resume, got %v", err)
	}
}

// TestDeriveKeyDeterministicForSameInputs confirms our HKDF
// construction is reproducible across runs — required for the
// Open path to succeed.
func TestDeriveKeyDeterministicForSameInputs(t *testing.T) {
	src := NewDeterministicSignal()
	samples, err := SampleWindow(src, 9, 0, 1000, 100)
	if err != nil {
		t.Fatalf("samples: %v", err)
	}
	salt := []byte("deterministic-salt-16b")
	k1, err := DeriveKey([]byte("secret"), 9, samples, salt)
	if err != nil {
		t.Fatalf("derive1: %v", err)
	}
	k2, err := DeriveKey([]byte("secret"), 9, samples, salt)
	if err != nil {
		t.Fatalf("derive2: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("DeriveKey non-deterministic: %x vs %x", k1, k2)
	}

	// Changing the binding secret must change the key — this
	// guards against an adversary who steals the blob AND
	// captures the environment but lacks the PUF secret.
	k3, err := DeriveKey([]byte("different-secret"), 9, samples, salt)
	if err != nil {
		t.Fatalf("derive3: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("DeriveKey produced the same key under different binding secrets")
	}
}

// TestAEADHeaderBindsParams confirms the aead header catches
// post-hoc parameter tampering — an attacker who copies the
// ciphertext and rewrites WindowStartMs to land "inside" a later
// window cannot succeed because the header goes into the AEAD
// tag.
func TestAEADHeaderBindsParams(t *testing.T) {
	src := NewDeterministicSignal()
	blob, err := Seal(src, []byte("secret"), 1, 100, 5000, 100, []byte("tamper-probe"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Mutate WindowStartMs to extend validity.
	tampered := *blob
	tampered.WindowStartMs = blob.WindowStartMs + 100000
	// Now-ms inside the fake window.
	_, err = Open(src, []byte("secret"), &tampered, 1, blob.WindowStartMs+100000+500)
	if err == nil {
		t.Fatal("tampered WindowStartMs succeeded — AEAD did not bind params")
	}
}
