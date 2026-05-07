# 963causal Red-Team Report — W8 Phase 1

- **Generated:** 2026-04-18T16:26:37Z
- **Harness:** `cmd/redteam` (in-process witnesses, fake drand chain)
- **Findings:** 20 total — 20 PASS · 0 FAIL · 0 DEFERRED

> All 20 attacks rejected as designed.

## Summary

| ID | Name | Category | Verdict | Duration |
|----|------|----------|---------|----------|
| RT-001 | DAQ aggregate signature bit-flip | `daq-forgery` | ✅ PASS | 34 ms |
| RT-002 | DAQ mask forgery (extra witness claimed) | `daq-forgery` | ✅ PASS | 25 ms |
| RT-003 | DAQ mask shrink below threshold | `daq-downgrade` | ✅ PASS | 15 ms |
| RT-004 | DAQ sequential chain reorder | `daq-forgery` | ✅ PASS | 28 ms |
| RT-005 | DAQ sequential chain truncation | `daq-downgrade` | ✅ PASS | 21 ms |
| RT-006 | DAQ op_hash tamper post-hoc | `daq-reuse` | ✅ PASS | 16 ms |
| RT-007 | Drand round substitution | `drand-freshness` | ✅ PASS | 6 ms |
| RT-008 | Drand signature bit-flip (simulated MITM) | `drand-forgery` | ✅ PASS | 2 ms |
| RT-009 | Witness /daq/sign without bearer token | `auth-bypass` | ✅ PASS | 0 ms |
| RT-010 | Witness /daq/sign with wrong bearer token | `auth-bypass` | ✅ PASS | 0 ms |
| RT-011 | PUF helper theft on foreign silicon | `puf-theft` | ✅ PASS | 433 ms |
| RT-012 | BDN rogue-key attack simulation | `bls-rogue-key` | ✅ PASS | 27 ms |
| RT-013 | Boiling-frog poisoning vs CUSUM drift detector | `puf-poisoning` | ✅ PASS | 0 ms |
| RT-014 | LBS post-enrolment full compromise cannot forge | `lbs-blindness` | ✅ PASS | 36 ms |
| RT-015 | TEB forced-ephemerality: pause-resume cannot re-open | `teb-replay` | ✅ PASS | 0 ms |
| RT-016 | Roster chain: attacker-owned DB cannot forge active roster | `roster-integrity` | ✅ PASS | 4 ms |
| RT-017 | Phoenix: rebirth protocol survives HW failure, rejects 6 abuse paths | `identity-continuity` | ✅ PASS | 3 ms |
| RT-018 | Emergency roster recovery: super-majority + waiting + announcement | `roster-emergency` | ✅ PASS | 3 ms |
| RT-019 | QEE: data recoverable across HW failure without master key | `data-continuity` | ✅ PASS | 12 ms |
| RT-020 | Phoenix multi-operator threshold rejects single-operator compromise | `identity-continuity` | ✅ PASS | 1 ms |

## Findings

### RT-001 — DAQ aggregate signature bit-flip

- **Verdict:** ✅ PASS
- **Category:** `daq-forgery`
- **Hypothesis:** attacker edits the BDN aggregate signature by one bit after the quorum is collected
- **Defence exercised:** BLS12-381 subgroup check + BDN pairing verify
- **Expected:** VerifyTicket returns error, attack rejected
- **Observed:** VerifyTicket PASS after single-bit aggregate tamper
- **Evidence:** `point is not on correct subgroup`
- **Duration:** 34 ms

### RT-002 — DAQ mask forgery (extra witness claimed)

- **Verdict:** ✅ PASS
- **Category:** `daq-forgery`
- **Hypothesis:** attacker sets an extra bit in the participation bitmask
- **Defence exercised:** BDN coefficient derivation covers the whole roster, not per-bit slot
- **Expected:** VerifyTicket returns error, aggregate does not verify
- **Observed:** VerifyTicket PASS with forged mask
- **Evidence:** `bls: invalid signature`
- **Duration:** 25 ms

### RT-003 — DAQ mask shrink below threshold

- **Verdict:** ✅ PASS
- **Category:** `daq-downgrade`
- **Hypothesis:** attacker clears mask bits hoping the verifier downgrades to a lower k
- **Defence exercised:** VerifyAggregate explicit CountEnabled >= minParticipants check
- **Expected:** VerifyTicket returns error citing threshold shortfall
- **Observed:** VerifyTicket PASS after clearing 2 mask bits
- **Evidence:** `daq: only 1 witnesses in aggregate, need ≥ 3`
- **Duration:** 15 ms

### RT-004 — DAQ sequential chain reorder

- **Verdict:** ✅ PASS
- **Category:** `daq-forgery`
- **Hypothesis:** attacker swaps adjacent witnesses in a sequential-mode ticket
- **Defence exercised:** WitnessInput(mode=sequential) binds prev_sig for every position > 0
- **Expected:** VerifyTicket fails at the position whose prev_sig no longer matches
- **Observed:** VerifyTicket PASS after swapping seq[0] and seq[1]
- **Evidence:** `daq/verify: witness seq=0 idx=1 sig: bls: invalid signature`
- **Duration:** 28 ms

### RT-005 — DAQ sequential chain truncation

- **Verdict:** ✅ PASS
- **Category:** `daq-downgrade`
- **Hypothesis:** attacker drops the last witness from a sequential chain below threshold
- **Defence exercised:** VerifyTicket explicit len(Witnesses) < threshold check
- **Expected:** VerifyTicket returns error citing chain length shortfall
- **Observed:** VerifyTicket PASS after truncating tail witness
- **Evidence:** `daq/verify: sequential chain length 2 < threshold 3`
- **Duration:** 21 ms

### RT-006 — DAQ op_hash tamper post-hoc

- **Verdict:** ✅ PASS
- **Category:** `daq-reuse`
- **Hypothesis:** attacker swaps op_hash to repurpose a ticket for a different operation
- **Defence exercised:** Agent Ed25519 signature over canonical request bytes
- **Expected:** VerifyAgentSignature returns error
- **Observed:** VerifyTicket PASS after swapping op_hash
- **Evidence:** `daq: agent signature invalid`
- **Duration:** 16 ms

### RT-007 — Drand round substitution

- **Verdict:** ✅ PASS
- **Category:** `drand-freshness`
- **Hypothesis:** attacker changes the round number while keeping the valid signature
- **Defence exercised:** VerifyDrandBeacon re-derives SHA256(round_be) and pairs against chain pub
- **Expected:** BLS verify fails (point does not pair to forged message)
- **Observed:** VerifyDrandBeacon PASS when round supplied ≠ round signed
- **Evidence:** `daq/drand: beacon signature invalid: bls: invalid signature`
- **Duration:** 6 ms

### RT-008 — Drand signature bit-flip (simulated MITM)

- **Verdict:** ✅ PASS
- **Category:** `drand-forgery`
- **Hypothesis:** attacker poisons the relay response with a one-bit-flipped beacon sig
- **Defence exercised:** VerifyDrandBeacon BLS pairing against pinned G2 chain pubkey
- **Expected:** BLS verify returns error
- **Observed:** VerifyDrandBeacon PASS after single-bit sig tamper
- **Evidence:** `daq/drand: beacon signature invalid: point is not on curve`
- **Duration:** 2 ms

### RT-009 — Witness /daq/sign without bearer token

- **Verdict:** ✅ PASS
- **Category:** `auth-bypass`
- **Hypothesis:** scanner calls /daq/sign with no Authorization header
- **Defence exercised:** Witness bearer-token guard (W7.B)
- **Expected:** HTTP 401 missing bearer token
- **Observed:** HTTP 401 returned before any signing work
- **Evidence:** `missing bearer token`
- **Duration:** 0 ms

### RT-010 — Witness /daq/sign with wrong bearer token

- **Verdict:** ✅ PASS
- **Category:** `auth-bypass`
- **Hypothesis:** attacker submits a random bearer token
- **Defence exercised:** Witness constant-time compare against stored SHA-256(token)
- **Expected:** HTTP 401 bad bearer token (constant-time)
- **Observed:** HTTP 401 rejected without signing
- **Evidence:** `bad bearer token`
- **Duration:** 0 ms

### RT-011 — PUF helper theft on foreign silicon

- **Verdict:** ✅ PASS
- **Category:** `puf-theft`
- **Hypothesis:** attacker with stolen helper data tries to reproduce K on a different host
- **Defence exercised:** HKDF commitment over K; codeword-XOR hides K unless PUF bits match
- **Expected:** Reproduce returns error (decode failure or commitment mismatch)
- **Observed:** Reproduce returned error on forged foreign silicon
- **Evidence:** `puf: commitment mismatch — silicon differs or too many bit-errors`
- **Duration:** 433 ms

### RT-012 — BDN rogue-key attack simulation

- **Verdict:** ✅ PASS
- **Category:** `bls-rogue-key`
- **Hypothesis:** attacker substitutes one roster slot with their own keypair, signs with it, hopes verifier accepts
- **Defence exercised:** BDN coefficients H(pk_i, {pk_0..pk_n}) bind the full roster; any swap changes every coefficient
- **Expected:** VerifyAggregate against the legitimate roster rejects the crafted aggregate
- **Observed:** VerifyAggregate PASS under poisoned roster
- **Evidence:** `bls: invalid signature`
- **Duration:** 27 ms

### RT-013 — Boiling-frog poisoning vs CUSUM drift detector

- **Verdict:** ✅ PASS
- **Category:** `puf-poisoning`
- **Hypothesis:** attacker raises per-bit BER by 1 %/day, hoping each single-day delta stays below any z-score radar
- **Defence exercised:** aggregate + per-bit CUSUM on Hamming distance since enrolment (W8.2)
- **Expected:** aggregate or per-bit CUSUM fires within 15 days of attack onset
- **Observed:** alarm fired on day 2 (BROAD_DRIFT); MTTA ≤ 15 satisfied
- **Evidence:** `first-alarm day=2 level=BROAD_DRIFT calibration-false-alarm-edges=1`
- **Duration:** 0 ms

### RT-014 — LBS post-enrolment full compromise cannot forge

- **Verdict:** ✅ PASS
- **Category:** `lbs-blindness`
- **Hypothesis:** attacker exfiltrates the entire agent state after enrolment and attempts to sign arbitrary messages
- **Defence exercised:** Shamir-split identity + tBLS-G1 signing (W11, ADR-009): agent holds no private share
- **Expected:** every forgery attempt rejected by Verify; Recover refuses to produce a valid σ without ≥ k partials
- **Observed:** post-enrolment compromise cannot produce a verifying signature under any of 5 attack paths
- **Evidence:** `honest σ=acfedcfbf048b3db… (48 B) verifies; attacks 1-5 all rejected`
- **Duration:** 36 ms

### RT-015 — TEB forced-ephemerality: pause-resume cannot re-open

- **Verdict:** ✅ PASS
- **Category:** `teb-replay`
- **Hypothesis:** attacker snapshots the VM with the sealed blob, resumes after window expiry, opens the secret
- **Defence exercised:** TEB Open() enforces window bounds + AEAD-binds header into tag (ADR-010)
- **Expected:** every post-window / wrong-zone / forged-env / tampered-header open rejected
- **Observed:** all 5 TEB adversarial paths rejected as specified
- **Evidence:** `window, zone, header-tamper, env-forge, and binding-secret guards all active`
- **Duration:** 0 ms

### RT-016 — Roster chain: attacker-owned DB cannot forge active roster

- **Verdict:** ✅ PASS
- **Category:** `roster-integrity`
- **Hypothesis:** attacker writes arbitrary bytes to the roster table after the legitimate chain is in place
- **Defence exercised:** hash-chained Epochs + pinned genesis ceremony + k-of-n transition sigs from the previous Epoch
- **Expected:** VerifyChain rejects every forgery variant (untrusted genesis, forged transition, chain splice/rollback)
- **Observed:** all four DB-write attacks rejected by the roster chain
- **Evidence:** `genesis ceremony = 3 pinned sigs, epoch threshold = 3`
- **Duration:** 4 ms

### RT-017 — Phoenix: rebirth protocol survives HW failure, rejects 6 abuse paths

- **Verdict:** ✅ PASS
- **Category:** `identity-continuity`
- **Hypothesis:** attacker hijacks service S by forging a rebirth request during the hardware-failure window
- **Defence exercised:** pinned operator key + ≥ k witness attestations + mandatory cool-down + append-only lineage (ADR-014)
- **Expected:** unpinned operator, below-k, short cool-down, replay, duplicate witness, spliced lineage all rejected
- **Observed:** all 6 abuse paths (unpinned op, below-k, early cool-down, replay, duplicate, splice) rejected
- **Evidence:** `r0 executed cleanly; every adversarial variant ErrRebirth-rejected`
- **Duration:** 3 ms

### RT-018 — Emergency roster recovery: super-majority + waiting + announcement

- **Verdict:** ✅ PASS
- **Category:** `roster-emergency`
- **Hypothesis:** attacker with k compromised witnesses rebuilds the chain via emergency path
- **Defence exercised:** super-majority (4-of-5) + 24h+ waiting + externally-pinned announcement (ADR-015)
- **Expected:** legit emergency succeeds; sub-super-majority and forged-announcement attempts fail
- **Observed:** legit emergency verifies; 3 abuse paths (sub-super-maj, short-wait, forged-announce) rejected
- **Evidence:** `emergency epoch activated at 86401000 ms with 4-of-5 current witnesses + 24h wait`
- **Duration:** 3 ms

### RT-019 — QEE: data recoverable across HW failure without master key

- **Verdict:** ✅ PASS
- **Category:** `data-continuity`
- **Hypothesis:** attacker with DB + operator key + k-1 witnesses can decrypt H₁'s sealed data
- **Defence exercised:** Shamir-split DEK + per-witness NaCl box + AEAD-bound (n, k) header (ADR-017)
- **Expected:** fast-path works on H₁; k-of-n recovery re-binds to H₂; below-k and 1-witness and threshold-tamper all fail
- **Observed:** fast path opens; k-of-n recovery + rebind to H2 works; 3 abuse paths rejected
- **Evidence:** `env: n=5 k=3 data_len=85 B; no single master key`
- **Duration:** 12 ms

### RT-020 — Phoenix multi-operator threshold rejects single-operator compromise

- **Verdict:** ✅ PASS
- **Category:** `identity-continuity`
- **Hypothesis:** attacker with ONE stolen operator key rebirths a service (bypassing M-of-N)
- **Defence exercised:** VerifyOperator enforces ≥ M distinct pinned operator signatures over Canonical() (ADR-018)
- **Expected:** 2-of-3 policy accepts 2 legit sigs, rejects 1 legit sig, rejects duplicated sig
- **Observed:** 2-of-3 legit pass; 1-of-3 reject; duplicate reject; rogue-op reject
- **Evidence:** `M-of-N threshold enforces distinct + pinned operator signatures`
- **Duration:** 1 ms

## Deferred (manual infra required)

These attacks cannot be executed by the Go harness alone; they require infrastructure the sandbox does not provide. Each is documented in `redteam/THREAT-MODEL.md` with the exact procedure an operator should follow when the environment is available.

| Attack | Why deferred | Manual procedure |
|--------|--------------|------------------|
| Emulator timing attack | Needs an agent running inside QEMU for hours, plus a real bare-metal baseline. The W5a z-score detector is the defence; measuring it against a live QEMU takes a full calibration cycle (~2 min) per run. | `docs/redteam/emulator-attack.md` — boot the agent inside QEMU, enrol, then run `puf-smoke --expect-tamper` and observe the z-score response. |
| VM live-migration | Needs control over the hypervisor. On cloud VMs without live-migration tooling this cannot be scripted. | `docs/redteam/live-migration.md` — trigger a vMotion / Nutanix live-migrate, watch `lastPufProofOk` flip to false within the next proof tick. |
| Kernel-module rootkit against Kernel Sentinel | Needs `CAP_SYS_MODULE`; cannot run in this sandbox. | `docs/redteam/kmod-sentinel-bypass.md` — load the rootkit, `kill -9 963causal-agent`, restart, confirm an AbsenceReport was posted with the gap. |
| Server-identity private-key theft | The DAQ server-identity seed lives in Prisma (`server_identities.privkey`). Theft means DB compromise, which the audit trail still records. An automated attack would require mutating DB state + watching for `DaqTicket.verdictOk = true`; this is W8 Phase 2 against the live control plane. | `docs/redteam/server-identity-rotation.md` — rotate via `UPDATE server_identities …`, confirm the next `executeDaq` uses the new pub, confirm old pre-rotation tickets still verify via `/verify`. |

