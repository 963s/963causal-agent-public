// Command redteam is the W8 attack harness. It brings up an
// isolated DAQ + PUF test environment (five in-process witnesses on
// random loopback ports, a fresh BDN roster, a synthetic agent
// identity, a pinned fake drand round signed with a throw-away key)
// and then tries to break the stack twelve different ways. Each
// attack is a self-contained function that returns a Finding; the
// harness aggregates the findings into a Markdown report on disk.
//
// Intent: turn the security claims in BSL §11, §13, and the various
// ADRs from "we designed this right" to "we have empirical evidence
// that all twelve straightforward attacks are rejected". The report
// is the hand-off to W9 (commercial 963causal Zero).
//
// Usage:
//
//   go run -buildvcs=false ./cmd/redteam
//   go run -buildvcs=false ./cmd/redteam --out /tmp/report.md
//   ./bin/redteam --out redteam/report.md --quiet   # CI mode
//
// Exit code: 0 if every attack was rejected as expected; non-zero
// if any Finding has Verdict != Pass. That makes the harness
// suitable for a Makefile / GitHub Actions gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Verdict is the narrow three-value status a Finding can carry.
type Verdict string

const (
	Pass     Verdict = "PASS"     // attack rejected exactly as designed
	Fail     Verdict = "FAIL"     // attack succeeded → gap discovered
	Deferred Verdict = "DEFERRED" // attack requires infra outside the harness
)

// Finding is the atomic unit of evidence the harness produces. One
// Finding = one attack run = one row in the report.
//
// Intentionally flat: no nested maps, no timestamps outside Duration
// (main.go stamps the run-level timestamp), no logger references.
// The whole struct is trivially serialisable and diffable.
type Finding struct {
	ID          string        // "RT-001"
	Name        string        // "DAQ aggregate signature bit-flip"
	Category    string        // "daq-forgery", "puf-theft", "auth-bypass", ...
	Hypothesis  string        // attacker goal, one sentence
	Defence     string        // defence-in-depth layer this exercises
	Expected    string        // what should happen
	Observed    string        // what actually happened
	Evidence    string        // one-line error message or hash
	Verdict     Verdict
	Duration    time.Duration
}

// Suite runs a full red-team pass.
type Suite struct {
	ctx      context.Context
	env      *Env
	findings []Finding
}

func main() {
	out := flag.String("out", "redteam/report.md", "Markdown report output path")
	quiet := flag.Bool("quiet", false, "only print the summary line to stdout")
	timeout := flag.Duration("timeout", 60*time.Second, "overall harness timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	env, err := NewEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "redteam: env setup failed: %v\n", err)
		os.Exit(2)
	}
	defer env.Close()

	s := &Suite{ctx: ctx, env: env}

	// Register attacks in numerical order so the report is stable
	// run-to-run. Add new attacks at the end of the slice; never
	// renumber existing ones — the ID is what operators cite in
	// tickets, changelogs, and BSL rollout rows.
	attacks := []func(*Suite) Finding{
		(*Suite).RT001_AggregateSigBitFlip,
		(*Suite).RT002_MaskForgeryExtraWitness,
		(*Suite).RT003_MaskShrinkBelowThreshold,
		(*Suite).RT004_SequentialChainReorder,
		(*Suite).RT005_SequentialChainTruncation,
		(*Suite).RT006_OpHashTamperPostHoc,
		(*Suite).RT007_DrandRoundSubstitution,
		(*Suite).RT008_DrandSigBitFlip,
		(*Suite).RT009_WitnessNoBearerToken,
		(*Suite).RT010_WitnessWrongBearerToken,
		(*Suite).RT011_PUFHelperTheftWrongSilicon,
		(*Suite).RT012_BDNRogueKeySimulation,
		(*Suite).RT013_BoilingFrogPoisoning,
		(*Suite).RT014_LBSPostEnrolCompromise,
		(*Suite).RT015_TEBForcedEphemerality,
		(*Suite).RT016_RosterChainForgeryRejected,
		(*Suite).RT017_PhoenixRebirthProtocolSound,
		(*Suite).RT018_EmergencyRosterRecovery,
		(*Suite).RT019_QEEAmnesiaSurvivable,
		(*Suite).RT020_MultiOperatorRebirthThreshold,
	}

	for _, fn := range attacks {
		start := time.Now()
		f := fn(s)
		f.Duration = time.Since(start)
		s.findings = append(s.findings, f)
		if !*quiet {
			fmt.Printf("  %-8s %-6s  %-50s  %6dms  %s\n",
				f.ID, f.Verdict, f.Name, f.Duration.Milliseconds(),
				oneLine(f.Evidence))
		}
	}

	passes, fails, deferrals := tally(s.findings)
	fmt.Printf("\n==> redteam: %d PASS  %d FAIL  %d DEFERRED  (elapsed %v)\n",
		passes, fails, deferrals, durationSince(s))

	if err := writeReport(*out, s.findings); err != nil {
		fmt.Fprintf(os.Stderr, "redteam: write report: %v\n", err)
		os.Exit(2)
	}
	if !*quiet {
		fmt.Printf("==> report: %s\n", *out)
	}

	if fails > 0 {
		os.Exit(1)
	}
}

func tally(fs []Finding) (pass, fail, deferred int) {
	for _, f := range fs {
		switch f.Verdict {
		case Pass:
			pass++
		case Fail:
			fail++
		case Deferred:
			deferred++
		}
	}
	return
}

func durationSince(s *Suite) time.Duration {
	var total time.Duration
	for _, f := range s.findings {
		total += f.Duration
	}
	return total
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// expectReject is a small DSL helper used by attacks. If err is
// nil the defence leaked — the attack succeeded, which is a FAIL.
// If err is non-nil, the defence held and the error text becomes
// the evidence.
func expectReject(err error) (Verdict, string) {
	if err == nil {
		return Fail, "attack unexpectedly succeeded (no error returned)"
	}
	return Pass, err.Error()
}

// sortFindings returns a stable-ordered copy. Kept here (not
// report.go) so tests can import it cleanly.
func sortFindings(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
