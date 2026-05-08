# 963causal Threat Model (W8+)

> **Revision**: 2026-05-08 — updated after the W8 Offensive Cryptographic
> & Red-Team Audit. New findings: C-01 (mlock), C-02 (CT-compare),
> C-03 (proc-spoofing), H-01 (σ-inflation), H-02 (low-and-slow),
> H-03 (eBPF caps), H-04 (symlink), H-05 (replay). See §2.3 for full
> catalogue. Remediation status tracked in §2.4.
> **C-03 and H-05 resolved 2026-05-08** via direct CPUID/MIDR_EL1 reads
> and signed frame timestamp+nonce binding.

> **Audience:** security auditor, site-reliability engineer, or
> customer's compliance officer deciding whether to rely on DAQ
> tickets as audit evidence.
>
> **Companion artefact:** `redteam/report.md` — the machine-generated
> attack-harness output. Every numbered row in §2 below links to
> the Finding that proves the defence held.

## 1. Scope and assumptions

**963causal is a continuity-of-trust layer, not a genesis-of-trust
layer.** It answers "is this host still the one we enrolled?" and
"has the host's behaviour drifted in a way the per-cycle checks
could individually miss?" It does NOT answer "was the host
genuine at boot?" (TPM / measured boot / signed image) or "is
the firmware uncompromised?" (remote attestation). This scope
statement is load-bearing; it is recorded in BSL ADR-007 and
every customer contract citing Ring -1 protection must cite both
ADR-007 and ADR-008 (SGRS).

963causal Runtime Integrity protects **runtime continuity** for Linux
hosts under three successive hostile hypotheses:

1. The host's silicon is unique per physical machine (PAL, W5).
2. The control plane's Next.js server is trustworthy enough to
   issue DAQ requests but MAY be fully compromised at some point
   after the fact (DAQ, W6). An attacker who steals the server's
   Ed25519 key cannot backdate a DAQ ticket because the drand
   round freshness must still fit the original wall clock.
3. The underlying kernel boot chain is measured separately (out of
   scope for W1–W8; a future W10+ ties in Linux IMA or TPM PCRs).
4. The silicon's per-bit error rate is roughly stationary under
   legitimate noise. Systematic drift is flagged as an attack by
   CUSUM (W8.2, §2.1 row 9 below).

What is **out of scope:**

- Attacks on drand itself (League of Entropy threshold BLS chain).
  We pin the chain's G2 public key and rely on it the way every
  other drand client does.
- Side-channel attacks on BLS12-381 pairings (kyber, kilic/bls12-381).
  We rely on the upstream library's constant-time guarantees.
- Physical cold-boot RAM extraction while the agent is live.
  **Partially mitigated (W8 audit):** the Ed25519 host private key and
  X25519 ephemeral are now locked via `unix.Mlock()` immediately after
  allocation and the systemd unit sets `LimitMEMLOCK=8M`. The PUF
  secret K lives in heap memory for only the duration of `Reproduce`;
  full TEE encapsulation remains a future W9+ goal (BSL §11.6).
- TPM/measured-boot chain (out of scope for W1–W8; future W10+).

## 2. Defence-in-depth map

| Layer | Protocol role | Test evidence |
|-------|----------------|----------------|
| W3 — External Witness (drand) | Request freshness anchor | RT-007, RT-008 (`report.md`) |
| W4 — Kernel Sentinel | Agent-is-alive detector | `CAP_BPF CAP_PERFMON` now granted in service file (W8 audit, H-03 fix). Manual procedure §3.3. |
| W5a — PUF z-score attestation | Silicon-has-not-moved signal (per-cycle) | **Deferred** — requires an emulator + baseline pair. See §3. |
| W5b — PUF-derived Ed25519 identity | Silicon-bound agent identity | RT-011 (`report.md`) |
| W6 — DAQ (aggregate BDN + drand) | ≥ k independent endorsements per sensitive op | RT-001, RT-002, RT-003, RT-004, RT-005, RT-006, RT-012 |
| W7 — Witness hardening | Auth + drand BLS verify + geographic distribution | RT-009, RT-010 (auth); RT-007, RT-008 (drand verify); geographic step is operator-driven (`deploy/docs/DEPLOY-WITNESSES.md`) |
| W8.1 — Red-team suite | Empirical confirmation of all of the above | `cmd/redteam`, this document |
| W8.2 — CUSUM drift detector | Cumulative silent-drift signal (slow poisoning) | RT-013 (`report.md`), `cmd/cusum-simulate`, unit tests in `internal/puf/cusum_test.go` |
| W8.3 — Memory hardening | `mlock()` on secret key material; swap-out prevention | W8 audit C-01 fix — `identity.MlockSecret()`, `LimitMEMLOCK=8M` in service file |
| W8.4 — CPUID cross-validation | Direct hardware register read cross-checks `/proc/cpuinfo`; mismatch = CRITICAL alert | W8 audit C-03 fix — `cpuid_amd64.s` + `cpuid_arm64.go` (MIDR_EL1 via kernfs) |
| W8.5 — Frame replay prevention | Signed `generated_at_ms` + 16-byte `frame_nonce` in every `Frame` proto | W8 audit H-05 fix — `proto/agent.proto` fields 13–14, populated in `buildFrame` |

### 2.1 Catalogue of cryptographic attacks covered

Every entry is a row in `redteam/report.md`. The ID format `RT-NNN`
is stable across reruns.

- **Aggregate signature bit-flips** (RT-001). A one-bit edit to
  the 48-byte BDN aggregate either fails the BLS12-381 G1 subgroup
  check (cheap reject, seen in practice) or, at probability
  2⁻¹²⁸, fails the pairing. Either outcome → rejected.

- **Mask tampering** (RT-002, RT-003). Adding or removing bits from
  the participation mask changes which BDN coefficients the
  verifier mixes in. Because `c_i = H(pk_i, pk_0..pk_n-1)` covers
  *all* roster pubkeys, an attacker cannot "peel off" a single
  coefficient; pairing fails. Below-threshold is caught even more
  cheaply, by the explicit `CountEnabled() >= k` check.

- **Sequential chain attacks** (RT-004, RT-005). Each sequential
  witness signs over `prev_sig`, so reordering two positions makes
  the second witness's signature verify against a different input
  than what's on the wire. Truncation is caught by the explicit
  length check.

- **Ticket reuse for a different operation** (RT-006). The agent
  Ed25519 signature covers `op_id ‖ op_hash ‖ drand_round ‖ ...`;
  post-hoc edits to any field break `VerifyAgentSignature`.

- **Drand freshness and MITM** (RT-007, RT-008). Witnesses do NOT
  rely on HTTPS alone; `VerifyDrandBeacon` BLS-verifies the round
  signature against a pinned G2 chain pubkey. A malicious relay
  serving a forged sig is rejected at the pairing step.

- **Witness bearer-token auth** (RT-009, RT-010). `/daq/sign`
  returns 401 in both the no-token and wrong-token cases without
  doing any cryptographic work, so an internet scanner cannot
  burn witness CPU.

- **PUF helper-data theft** (RT-011). Replaying `puf.keystore.json`
  on a silicon whose PUF bits are statistically independent of
  the original produces a decoded K that HKDF commits to a
  different hash; the commitment check fails. We model "foreign
  silicon" as uniformly-random bits, which is the strongest
  adversary this decoded-then-verify construction can defend
  against.

- **BDN rogue-key attack** (RT-012). A poisoned roster (attacker
  substitutes one slot with their own keypair) changes the BDN
  coefficients used to derive the aggregate pubkey; the aggregate
  from the honest roster no longer verifies under the poisoned
  roster. Because both roster and coefficient hash cover the full
  set, the attacker cannot "cancel" their fake pubkey out.

- **Boiling-frog poisoning** (RT-013). A slow-drift adversary
  flips PUF bits by a "within natural noise" delta each cycle
  (the explicit threat: 1 % per day). Per-cycle z-score checks
  let every single day through; over 30–50 cycles the fingerprint
  is substantively rewritten. Two-sided CUSUM on Hamming distance
  (aggregate detector) plus Bernoulli-tuned per-bit CUSUM
  (targeted-attack detector) catches the drift *within 3 days*
  of onset in the RT-013 simulation. Mathematical spec in
  `internal/puf/cusum.go`; parameter choice follows Page 1954
  and Lucas 1985. Detector has empirical ARL₀ ≈ 200 cycles under
  the null (measured over 400-cycle runs at p₀ = 0.5 %), far
  above any production recalibration cadence.

- **CUSUM σ-inflation during calibration** (OPEN — H-01). An attacker
  who controls the host during the first 8 calibration cycles can inflate
  `σ` artificially, making the detector permanently insensitive. No
  current `σ_max` ceiling is enforced. Mitigation requires an
  architecture-specific `σ` bound derived from fleet baseline data.
  See §3.6 for the manual reproduction procedure.

- **Low-and-slow below CUSUM slack** (OPEN — H-02). Any per-cycle
  Hamming shift `δ < K = 0.5σ` is absorbed by the slack parameter and
  never accumulates. A rotating-bit attacker (different bit flipped each
  cycle) can drift ~100 bits over 25 days without triggering either
  detector. Mitigation: a 50-cycle Shewhart sliding-window complement to
  the CUSUM. See §3.7 for the manual reproduction procedure.

- **Frame replay before drand anchor** (✅ **FIXED — H-05**). `Frame`
  proto now carries `generated_at_ms` (field 13) and `frame_nonce` (field 14),
  both included in the serialised `frame_blob` that Ed25519 signs.
  Any attacker who replays a captured frame intact will be rejected by
  the server’s timestamp window check. Any attacker who edits `generated_at_ms`
  to appear fresh breaks the signature. Nonce tracking prevents exact-copy
  replay within the window. Implementation: `proto/agent.proto`, `proto/agent.pb.go`,
  `cmd/963causal-agent/main.go:buildFrame`.

- **HW fingerprint `/proc`-spoofing** (✅ **FIXED — C-03**). CPU identity
  now comes from direct hardware register reads:
  - **amd64**: `CPUID` instruction via `internal/identity/cpuid_amd64.s`
    (leaves 0, 1, 0x80000002–4 for vendor, family/model/stepping, brand string).
  - **arm64**: `MIDR_EL1` via `/sys/devices/system/cpu/cpu0/regs/identification/`
    (kernfs path, not interceptable by `/proc`-layer rootkits).
  At runtime, `HardwareFingerprint()` cross-validates the register value
  against `/proc/cpuinfo`; a mismatch logs `CRITICAL` and uses the
  hardware register value for the fingerprint hash.
  Memory total now uses `sysinfo(2)` syscall before `/proc/meminfo`.

### 2.2 What RT-011 does NOT model

The in-process simulation of "foreign silicon" uses uniformly
random bits, which is *harder* than what a real attacker on a
different Ampere Altra host would face: real hosts would still be
statistically similar (same architecture, same kernel scheduler
behaviour). The claim "Reproduce fails on a different host" is
therefore proven *from above* — a near-identical host is merely
less extreme than the synthetic worst-case RT-011 already
defeats. A paranoid operator should still run the physical
live-migration attack from §3.

## 3. Attacks the harness cannot automate

These need infrastructure the sandbox does not grant. Each has an
explicit procedure so a human operator can reproduce it on the
intended target environment.

### 3.1 Emulator attack (targets W5a)

Goal: prove that running the agent inside QEMU triggers a PUF-drift
verdict because software-emulated timing differs from bare metal.

Procedure:
1. Boot the agent on bare-metal Ampere Altra; let it enrol (PAL).
2. Snapshot `/var/lib/963causal/` and the agent binary.
3. Restore the snapshot inside `qemu-system-aarch64 -cpu max`.
4. Run `bin/puf-smoke --attest-once`.
5. **Expected:** `verdict = DRIFT` or `TAMPER`, max|z| > 5.0.

Record the observed z-score vs. the 95th-percentile seen in the
natural baseline (BSL §11); anything ≥ 3× the natural max is
strong evidence of emulator detection. If QEMU passes, either
(a) tune the loops in `internal/puf/ring.go` so emulation shows
up more sharply, or (b) accept that W5a is soft on emulators and
lean harder on W5b (whose key derivation fails whenever BER
exceeds the Hamming(7,4) tolerance — emulators typically
produce 30%+ BER).

### 3.2 Live-migration attack (targets W5a + W5b)

Goal: prove that a live-migrated VM (vMotion, Nutanix Move,
Proxmox live-migrate) is flagged within one attestation interval.

Procedure:
1. Run the agent inside a VM on hypervisor A; wait for at least
   one green PAL attestation and one PUF-key proof.
2. Live-migrate to hypervisor B (different CPU stepping).
3. Watch for the next `puf.attest` tick. **Expected:** `DRIFT` or
   `TAMPER` verdict; `lastPufProofOk` flips to false (K reproduce
   diverges because the V3 quantiser's cross-core ratios shift).
4. Check `DaqTicket` with `opKind = "host.delete"` is refused if
   the operator attempts one (PUF-key attestation must succeed
   before DAQ fires; the gate fails closed).

### 3.3 Kernel-module rootkit against Kernel Sentinel

Goal: prove the pinned eBPF timer survives the agent being killed
and reports the gap on next boot.

Procedure:
1. Observe a steady stream of `pulse` events.
2. `sudo kill -9 $(pidof 963causal-agent)`.
3. Wait ≥ 30 seconds (Sentinel's `MaxSilenceSeconds`).
4. `systemctl start 963causal-agent`.
5. **Expected:** the agent's first action is to post an
   `AbsenceReport` listing the observed gap; the server opens a
   `sentinel.absence` alert.

### 3.4 Ring -1 TOCTOU against SGRS (targets W9 / 963causal Zero)

Goal: prove that a hypervisor-level attacker can extract a
plaintext secret from the agent's address space during the ~1 ms
window in which Silicon-Gated Remote Signing (SGRS) holds it.
See BSL ADR-008 for the naming rejection and the honest
residual-risk disclosure.

Procedure:

1. Provision a host with SGRS enrolled and a known test secret
   `S = "canary-ring-minus-one-test-vector"` at a dummy
   operation id `OP_TEST`.
2. From the hypervisor (KVM), attach VMI via `libvmi` or
   equivalent and set a breakpoint on the agent process's
   `sgrs.Sign` entry (assumes symbols; strip them for a harder
   test).
3. When the breakpoint hits, dump a 4-KiB window around the
   register holding the secret pointer.
4. **Expected (SGRS without enclave):** `S` is present in the
   dump for ~single-digit ms. The attack SUCCEEDS. This is the
   explicit limit documented in ADR-008 and
   `redteam/THREAT-MODEL.md` §1: SGRS does NOT defeat Ring -1.
5. **Expected (SGRS inside SEV-SNP / Nitro / TDX):** the memory
   window is encrypted and inaccessible to the hypervisor. The
   dump reveals ciphertext or zeros. Attack FAILS.

What this test proves is the *asymmetry*: SGRS alone is a
product-grade defence against userspace and most Ring-0 attackers
(the window is too short for opportunistic dumping) but not a
product-grade defence against Ring -1. Customers who need
Ring -1 protection MUST deploy SGRS inside an enclave; the
agent's `--enclave-mode` flag (W9) consumes that constraint.

The harness does NOT run this test automatically because (a) it
needs libvmi + root on the hypervisor, and (b) shipping a tool
that dumps guest memory on demand is itself a loaded weapon
better left to the customer's internal red team.

### 3.5 Server-identity private-key theft (targets W6)

Goal: prove that rotating the control-plane's own Ed25519 key
invalidates future DAQ tickets but keeps old ones verifiable.

Procedure:
1. Capture a valid `DaqTicket` row (e.g. by running `host.delete`
   on a throwaway host).
2. Rotate the server identity:

       UPDATE server_identities
       SET privkey = $new_seed, pubkey = $new_pub, rotatedAt = NOW()
       WHERE label = 'default';

3. Trigger a new DAQ round; confirm it uses the new pubkey.
4. Re-verify the captured ticket via
   `POST http://127.0.0.1:17090/verify` with the ticket's
   original roster — it MUST still verify, because the ticket
   only needs the *agent_pubkey embedded in the request*, not
   whatever `server_identities` currently holds.
5. If step 4 fails, that means `lib/daq.ts verifyDaqTicket` is
   looking up the current server identity instead of trusting
   the embedded one; that is a bug worth opening.

## 3.6 CUSUM σ-inflation (targets H-01)

Goal: prove that injecting controlled noise during calibration makes
the detector permanently insensitive.

Procedure:
1. Enrol a host and immediately run 8 calibration cycles while a
   CPU-burn process creates ~4× natural timing jitter.
2. Capture the resulting CUSUM `σ` (should be inflated vs. the
   fleet baseline ≈ 2.1 on Altra).
3. Remove the CPU-burn process. Run 30 attestation cycles with
   a Hamming shift of +5 bits/cycle (roughly 2.5× the natural δ).
4. **Expected (if vulnerable):** zero CUSUM alarms. `σ_inflated`
   means `H = 5σ_inflated` is too large for the attack to cross.
5. **Fix:** add `if sigma > 6.0 { return error("calibration noise
   exceeds σ_max=6.0") }` in `Calibrate()`.

### 3.7 Low-and-slow CUSUM poisoning (targets H-02)

Goal: prove that a rotating-bit attacker stays below both CUSUM paths.

Procedure:
1. Calibrate a fresh CUSUM on 20 clean cycles (`μ ≈ 4`, `σ ≈ 2.1`).
2. Run `Observe()` for 100 cycles, each flipping a different bit
   from the reliable-bit pool (simulate with `ComputeBitDelta`).
   Hamming distance per cycle = 1 (below `K ≈ 1.05`).
3. **Expected (if vulnerable):** `AggregateFired = false`,
   `PerBitFired = false` throughout all 100 cycles. The fingerprint
   has drifted 100 bits but the detector never fired.
4. **Fix:** implement a 50-cycle sliding Shewhart chart on the
   Hamming distance mean and add it as a `SLOW_DRIFT` verdict level.

## 4. Known gaps, deferred to later phases

- **W8 Phase 3.** Repeat the cryptographic attacks against the
  *live* PM2 stack (control plane + Prisma + real witnesses).
  Covers the DB-level defences: unique `opId`, `consumed` flag
  transaction, replay of a `DaqTicket` JSON against the
  `/verify` endpoint, `/api/admin/hosts/:id/delete` under
  adversarial conditions.
- **CUSUM σ_max ceiling (H-01).** Add an architecture-specific
  upper bound on calibration `σ` in `Calibrate()`. Fleet data
  required to set the constant per CPU family.
- **CUSUM Shewhart complement (H-02).** 50-cycle sliding mean
  detector for sub-slack low-and-slow attacks, emitting
  `SLOW_DRIFT` verdict. See §3.7.
- **CUSUM server integration.** The detector is proven in
  simulation and via RT-013; the Prisma state table + /api/agent/puf/attest
  wiring + recalibration-gate hook are still TODO (BSL §13.8).
- **W9 — 963causal Zero / SGRS.** The ADR-008 naming + threat
  disclosure is on the ledger; the implementation is not. When
  it ships, §3.4 of this doc becomes a live Phase-2 procedure
  customers can run themselves.
- **TEE integration.** PAL-derived keys still live briefly in
  agent RAM during Reproduce. A future phase ties K to an SEV-SNP
  / TDX / ARM CCA attestation so the Reproduce path stays
  entirely inside the enclave. BSL §11.6 tracks this.
- **Server-side frame replay enforcement.** The agent now signs
  `generated_at_ms` and `frame_nonce` in every frame, but the
  server must enforce the timestamp window (`|recv−gen| ≤ 2×epoch`)
  and track nonces in a short-lived Redis/Postgres set. This is
  a server-side TODO; the cryptographic foundation is laid.

## 5. Running the harness

```bash
cd 963causal-agent
go build -buildvcs=false -o bin/redteam ./cmd/redteam
./bin/redteam --out redteam/report.md
# or in CI:
./bin/redteam --quiet --out redteam/report.md
```

Exit code is 0 iff every attack returned `PASS`. CI should reject
any merge that flips a finding from `PASS` to `FAIL`; a flip from
`PASS` to `DEFERRED` is also a warning sign (it means the harness
no longer exercises the defence).

Adding a new attack: append to the `attacks` slice in
`cmd/redteam/main.go`, implement a `RTxxx_...(s *Suite) Finding`
method, and never renumber existing IDs.
