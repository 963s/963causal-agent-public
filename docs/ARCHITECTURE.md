# Architecture reference

The agent ships as one static binary (`CGO_ENABLED=0`, `-buildmode=pie`).

## Enrollment and encrypted payload

Probe logic is not left in clear text on disk. The shipped binary holds an encrypted payload. The key material used to decrypt it comes from a control plane handshake and stays in RAM; it is not written to disk as a long lived secret.

```
 agent                         control plane
   |                                |
   | 1. Ed25519 + X25519 keys       |
   |    hw_fp = SHA3(cpu|mem|id)    |
   |                                |
   | 2. POST /api/agent/enroll      |
   |    license, ed_pub, x_pub,     |
   |    hw_fp, hostname, os, ...    |
   |------------------------------->|
   |                                | 3. validate license,
   |                                |    derive session key,
   |                                |    encrypt probe config
   |                                |
   | 4. host_id, agent_token,       |
   |    server_x_pub,               |
   |    encrypted_payload, nonce,    |
   |    heartbeat_interval, ...     |
   |<-------------------------------|
   |                                |
   | 5. derive session_key,         |
   |    decrypt probe_cfg in RAM,   |
   |    start probes                |
   |                                |
   | 6. POST /api/agent/frame       |
   |    signed frames (with retry)  |
   |------------------------------->|
   |                                |
   | 7. POST /api/agent/heartbeat   |
   |------------------------------->|
   |                                | revoke if grace expires
```

### Enrollment resilience

Enrollment uses exponential backoff with jitter (up to 10 attempts) so a temporarily-unavailable control plane does not crash-loop the agent through systemd `Restart=on-failure`. All egress POST calls (frames, attestations, proofs) also retry with backoff (up to 3 attempts, base 2s × 2^attempt, capped at 60s).

### Notes

- Host signing keys are created under `internal/identity` and stored at `keystore_path`. Private signing material is not sent to the operator as a reusable impersonation secret in the way an API password would be; enrollment ties the host to hardware policy checked server side.
- Frames use Ed25519 over the protobuf payload; heartbeats sign a fixed tuple that includes host id, sequence, and time. TLS carries the bytes; after enroll, protobuf bodies carry the session token the server issued.
- Static Linux builds: `make release` with `CGO_ENABLED=0`. Install helper: `scripts/install-agent-from-url.sh`.
- The control plane must validate licenses, verify signatures on ingest, and rate limit abusive clients.

### Operational notes

- Plain probe logic does not ship inside the binary without going through the encrypted payload path described above.
- Moving the binary to another machine does not grant the same trust: license binds to `hw_fingerprint`, and session keys are per host.
- If heartbeats stop beyond `grace_period_sec`, the agent clears session state and stops probing until it can enroll again.
- Rotating server keys invalidates open sessions on the next expected handshake.

## Key lifecycle and memory wiping

Sensitive key material follows strict lifecycle discipline:

| Key | Lifetime | Wiping |
|-----|----------|--------|
| Ed25519 host key (`hk.EdPrivate`) | Process lifetime (needed for signing) | `defer hk.Zero()` on main exit |
| X25519 ephemeral key | Per-enrollment handshake | `defer ecdh.Zero()` |
| Session key (ChaCha20) | Per-enrollment | `defer payload.Zero(sessionKey)` |
| ECDH shared secret | Derivation scope | `defer payload.Zero(shared)` |
| PUF secret K | Single function scope | Zeroed immediately after Ed25519 derivation |
| PUF-derived Ed25519 private | Single proof scope | Zeroed after signing in `ProveKey` |

Constant-time comparisons use `crypto/subtle.ConstantTimeCompare` throughout.

## Kernel Sentinel (eBPF)

A pinned eBPF program (`/sys/fs/bpf/963causal/`) continues running inside the kernel when the userspace agent is killed. The agent heartbeats into `pulse_map`; a kernel `BPF_TIMER` detects silence and records `absence_event`s on a ringbuf. On the next agent start, we drain the ringbuf and ship findings to the server.

This provides **absence detection**: proof that the agent was killed, crashed, or failed to pulse, even if the adversary cleaned up before the next boot.

## PUF Attestation Layer (W5a / W5b)

### W5a — Silicon fingerprinting

Per-core micro-benchmark loops (integer ALU, memory stride, branch predictor, FPU chain, SipHash mixer) produce timing distributions that are unique to the physical CPU. The distributions are quantized into a stable bit vector using gray-coded bucket boundaries. Cross-run comparison uses Hamming distance with z-score thresholds.

### W5b — Fuzzy key extraction

A fuzzy extractor (Hamming(7,4) error-correcting code + helper data) derives a deterministic 128-bit secret from the PUF measurement. The secret derives an Ed25519 keypair; periodic proof-of-possession signatures prove the agent is running on the enrolled silicon without transmitting the secret.

### CUSUM drift detection

Dual-path Cumulative Sum control chart detects slow "boiling-frog" poisoning of PUF bits:

1. **Aggregate CUSUM** — catches broad-spectrum drift (many bits shifting slowly).
2. **Per-bit CUSUM** — catches targeted attacks (few bits shifting fast) with Bonferroni-corrected family-wise error rate.

Both run in parallel; when both fire simultaneously, the verdict escalates to `CRITICAL`.

## Multi-Source Time Consensus (MSTC)

The Physics Layer probe samples four independent time sources per frame:

- **HW** — architecture-specific counter (ARM `CNTVCT_EL0`, x86 `RDTSC`)
- **HW2** — alternate hardware path (ARM `CNTPCT_EL0`, x86 `RDTSCP`)
- **VDSO** — `clock_gettime(CLOCK_MONOTONIC_RAW)` via vDSO fast path
- **SYSCALL** — forced `SYS_clock_gettime` bypassing vDSO

Ratio divergence between these sources detects hypervisor live-migration, vDSO interception by rootkits, and hardware read trapping.

## External Witness (drand)

Each frame carries a fresh randomness value from the League of Entropy drand beacon chain (BLS12-381 threshold signatures from 15+ independent operators). This anchors the frame to a specific moment in time: an attacker who captures keys cannot fabricate "fresh-looking" frames offline because the beacon round is unpredictable before its drawing.

## DAQ — Distributed Attestation Quorum

For sensitive operations, the agent collects k-of-n BLS12-381 threshold signatures from independent witness nodes. Two modes:

- **Parallel** — all witnesses contacted concurrently; first k aggregated via BDN.
- **Sequential** — chain mode where each witness signs over the previous witness's signature.

## Layout

```
cmd/963causal-agent/     entry point + main loop
internal/identity/       Ed25519 host key, X25519 ECDH, hardware fingerprint
internal/license/        enroll client, heartbeat, frame/PUF post + retry/backoff
internal/payload/        session key derivation (HKDF-SHA3), ChaCha20-Poly1305 decrypt
internal/probe/          MSTC, syscall latency probes, drand witness, scheduler stats
internal/histogram/      epoch histograms for syscall distributions
internal/sculpture/      genotype side of sculpture pipeline
internal/config/         YAML configuration
internal/puf/            PUF measurement, quantization (V1/V2/V3), fuzzy extractor,
                         CUSUM drift detection, Hamming codec, key lifecycle
internal/sentinel/       eBPF kernel sentinel (absence detection)
internal/daq/            distributed attestation quorum (BLS threshold, drand anchor)
internal/qee/            quantum entropy envelope (Shamir secret sharing)
internal/earpack/        EAR CBOR evidence packaging
internal/teb/            time-entropy binding
internal/lbs/            location-bound sealing
internal/siliconcert/    silicon certificate generation
proto/                   protobuf wire format
packaging/               systemd service, install scripts
scripts/                 download and install helpers
redteam/                 threat model + red team tools (not part of a normal install)
```

## Build

```bash
make release                  # both targets
make release-linux-amd64      # single target
VERSION=1.2.3 make release    # inject specific version
```

Build flags: `CGO_ENABLED=0`, `-buildmode=pie`, `-trimpath`, `-ldflags="-s -w"`, `-buildvcs=false`.
