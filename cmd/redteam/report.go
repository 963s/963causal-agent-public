package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeReport emits a Markdown file summarising every Finding.
// Layout: metadata block, summary table, then one section per
// finding with expected / observed / evidence. Designed so the
// output can be committed to the repo and diffed between runs.
func writeReport(path string, findings []Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	pass, fail, deferred := tally(findings)
	total := len(findings)

	fmt.Fprintf(&b, "# 963causal Red-Team Report — W8 Phase 1\n\n")
	fmt.Fprintf(&b, "- **Generated:** %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Harness:** `cmd/redteam` (in-process witnesses, fake drand chain)\n")
	fmt.Fprintf(&b, "- **Findings:** %d total — %d PASS · %d FAIL · %d DEFERRED\n\n", total, pass, fail, deferred)

	if fail > 0 {
		fmt.Fprintf(&b, "> **⚠ REGRESSION:** one or more attacks succeeded where the defence should have held. Fix before merging.\n\n")
	} else if deferred > 0 {
		fmt.Fprintf(&b, "> %d findings deferred; see each row for what the harness could not simulate.\n\n", deferred)
	} else {
		fmt.Fprintf(&b, "> All %d attacks rejected as designed.\n\n", pass)
	}

	// ---- Summary table -----------------------------------------------------
	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "| ID | Name | Category | Verdict | Duration |")
	fmt.Fprintln(&b, "|----|------|----------|---------|----------|")
	for _, f := range findings {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %d ms |\n",
			f.ID, f.Name, f.Category, badge(f.Verdict), f.Duration.Milliseconds())
	}
	fmt.Fprintln(&b, "")

	// ---- Detailed sections -------------------------------------------------
	fmt.Fprintln(&b, "## Findings")
	fmt.Fprintln(&b, "")
	for _, f := range findings {
		fmt.Fprintf(&b, "### %s — %s\n\n", f.ID, f.Name)
		fmt.Fprintf(&b, "- **Verdict:** %s\n", badge(f.Verdict))
		fmt.Fprintf(&b, "- **Category:** `%s`\n", f.Category)
		fmt.Fprintf(&b, "- **Hypothesis:** %s\n", f.Hypothesis)
		fmt.Fprintf(&b, "- **Defence exercised:** %s\n", f.Defence)
		fmt.Fprintf(&b, "- **Expected:** %s\n", f.Expected)
		fmt.Fprintf(&b, "- **Observed:** %s\n", f.Observed)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:** `%s`\n", escapeEvidence(f.Evidence))
		}
		fmt.Fprintf(&b, "- **Duration:** %d ms\n\n", f.Duration.Milliseconds())
	}

	// ---- Out-of-band attacks ----------------------------------------------
	fmt.Fprintln(&b, "## Deferred (manual infra required)")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "These attacks cannot be executed by the Go harness alone; they require infrastructure the sandbox does not provide. Each is documented in `redteam/THREAT-MODEL.md` with the exact procedure an operator should follow when the environment is available.")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "| Attack | Why deferred | Manual procedure |")
	fmt.Fprintln(&b, "|--------|--------------|------------------|")
	fmt.Fprintln(&b, "| Emulator timing attack | Needs an agent running inside QEMU for hours, plus a real bare-metal baseline. The W5a z-score detector is the defence; measuring it against a live QEMU takes a full calibration cycle (~2 min) per run. | `docs/redteam/emulator-attack.md` — boot the agent inside QEMU, enrol, then run `puf-smoke --expect-tamper` and observe the z-score response. |")
	fmt.Fprintln(&b, "| VM live-migration | Needs control over the hypervisor. On cloud VMs without live-migration tooling this cannot be scripted. | `docs/redteam/live-migration.md` — trigger a vMotion / Nutanix live-migrate, watch `lastPufProofOk` flip to false within the next proof tick. |")
	fmt.Fprintln(&b, "| Kernel-module rootkit against Kernel Sentinel | Needs `CAP_SYS_MODULE`; cannot run in this sandbox. | `docs/redteam/kmod-sentinel-bypass.md` — load the rootkit, `kill -9 963causal-agent`, restart, confirm an AbsenceReport was posted with the gap. |")
	fmt.Fprintln(&b, "| Server-identity private-key theft | The DAQ server-identity seed lives in Prisma (`server_identities.privkey`). Theft means DB compromise, which the audit trail still records. An automated attack would require mutating DB state + watching for `DaqTicket.verdictOk = true`; this is W8 Phase 2 against the live control plane. | `docs/redteam/server-identity-rotation.md` — rotate via `UPDATE server_identities …`, confirm the next `executeDaq` uses the new pub, confirm old pre-rotation tickets still verify via `/verify`. |")
	fmt.Fprintln(&b, "")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// badge returns the Markdown-friendly badge for a verdict.
func badge(v Verdict) string {
	switch v {
	case Pass:
		return "✅ PASS"
	case Fail:
		return "❌ FAIL"
	case Deferred:
		return "⚠️ DEFERRED"
	default:
		return string(v)
	}
}

// escapeEvidence makes the single-line evidence snippet safe for a
// Markdown code span. Backticks would close the span early; a
// simple substitution with the unicode modifier grave accent keeps
// the visual appearance while guaranteeing the span stays intact.
func escapeEvidence(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "`", "ˋ")
	if len(s) > 180 {
		return s[:177] + "..."
	}
	return s
}
