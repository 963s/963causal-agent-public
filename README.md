<p align="center">
  <img src="assets/963causal-mark.svg" alt="963causal" width="72" height="72" />
</p>

<h1 align="center">963causal Agent</h1>

<p align="center">
  <strong>Open-source runtime probe for Linux hosts.</strong><br />
  Passive telemetry · Signed frames · Auditable codebase
</p>

<p align="center">
  <a href="https://963causal.com">Website</a> ·
  <a href="https://963causal.com/verify">Verify integrity (public portal)</a>
</p>

---

## What this repository is

This repository contains **only** the **963causal Agent** — the component that runs on customer servers, collects **physically grounded timing and noise signals** from the running kernel and userspace (within documented probes), and ships **cryptographically signed telemetry** to your configured control plane.

It does **not** contain proprietary scoring engines, insurance certificate issuance logic, or HQ analytics. Those live in **private** infrastructure. That separation is intentional: auditors can review **exactly** what runs on the host without wading through unrelated algorithms.

---

## Nature of the agent

The agent acts as a **passive / bounded data collector**:

- It measures **stable, declarative signals** (timing ratios, witness-backed randomness anchors where configured, PUF-related attestations when enrolled, etc.) — not keystrokes, file contents, or application payloads.
- Probe configuration is **delivered encrypted** after license-bound enrollment; the binary on disk does **not** embed hidden probe logic — see `README.md` (original technical overview) under **Identity-bound encryption handshake** in-repo.
- Network outbound traffic is **TLS** to your operator’s control plane; frames are **Ed25519-signed** so the server can reject forged telemetry.

This design supports **transparency**: there is no “secret branch” of behaviour inside the public tree — what you build from this source is what runs (modulo your licensed payload from the control plane).

---

## Transparency & audit

| Topic | What to review |
|--------|----------------|
| **Main entrypoint** | `cmd/963causal-agent/` |
| **Enrollment & session crypto** | `internal/license/`, `internal/payload/`, `internal/identity/` |
| **Signed outbound frames** | `proto/agent.proto`, protobuf wiring in `cmd/` / `internal/` |
| **Kernel-facing probes** | `internal/probe/`, `internal/sentinel/` (optional eBPF — best-effort on hardened systemd units) |
| **Operational packaging** | `packaging/`, `scripts/install-agent-from-url.sh` |

Third parties are encouraged to **diff releases against tags**, **reproducibly build** (`make release`), and compare hashes with published release artifacts.

---

## Security model (short)

1. **At rest (customer host):** Ed25519 signing keys are stored locally (`keystore_path` in config); private keys are not uploaded to 963causal as usable long-term secrets for impersonation of the customer’s workload — enrollment binds identity to hardware fingerprinting policy enforced server-side.
2. **In transit:** HTTPS to the control plane; application-layer signatures on telemetry frames.
3. **Payload secrecy:** Encrypted probe bundle decrypted only after successful handshake; session keys are volatile (see `internal/payload/session.go`).

For a deeper threat-oriented discussion, see `redteam/THREAT-MODEL.md` (research / QA tooling under `cmd/redteam/` is **not** required for production installs).

---

## Quick install (binary)

Published releases attach static Linux binaries (`amd64`, `arm64`). After your operator provides a **download URL** and **license key**:

```bash
sudo CAUSAL_DOWNLOAD_URL="https://github.com/963s/963causal-agent-public/releases/download/<tag>/963causal-agent_linux_amd64.tar.gz" \
  bash scripts/install-agent-from-url.sh
```

Then create `/etc/963causal/agent.yaml` with at least:

```yaml
control_plane_url: "https://your-control-plane.example"
license_key: "<from your operator>"
keystore_path: "/var/lib/963causal/host.key"
log_level: "info"
```

See `packaging/install.sh` for a fuller guided install when packaging artifacts are laid out next to it.

---

## Build from source

Requirements: **Go** (see `go.mod` for the declared toolchain version).

```bash
git clone https://github.com/963s/963causal-agent-public.git
cd 963causal-agent-public
make release          # outputs under bin/
# or single-target:
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/963causal-agent ./cmd/963causal-agent
```

Run:

```bash
./bin/963causal-agent -config /path/to/agent.yaml
```

---

## Verify certificates / Causal ID (end users)

After enrollment, customers receive a **Causal ID** and related artefacts through your operator’s flows. **Public verification** of integrity artefacts is documented at:

**https://963causal.com/verify**

(Operator-specific EAR / COSE exports may use additional endpoints — your operator documents those.)

---

## Repository hygiene

This tree is scrubbed for operator secrets before publication:

- No `.git` history from the private monorepo (fresh history starts here).
- No committed `.env`, host keys, or PEM material.
- Internal lab IPs in **test code** may still use `127.0.0.1` — that is standard loopback for unit tests, not production infrastructure.

---

## License

See `LICENSE` if present; otherwise refer to the license file added by the publisher for this public mirror.

---

## Contact

Operator support and enterprise documentation are provided through **963causal** commercial channels linked from [963causal.com](https://963causal.com).
