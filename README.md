# 963causal Agent

<img src="assets/963causal-mark.svg" width="56" height="56" alt="963causal logo">

Linux agent that collects runtime timing and noise signals, signs its telemetry, and sends it to your control plane over TLS. This repository is the agent only. Analysis engines, underwriting workflows, and operator dashboards are not included; they stay on private systems so reviewers can focus on what actually runs on the host.

More detail on enrollment crypto and package layout: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What it does

The process is measurement heavy, not content invasive. It records structured signals such as timing ratios and, where enabled, witness or PUF attestations. It does not read keystrokes, file bodies, or application data. After a licensed enroll step, probe settings arrive encrypted; the on disk binary does not hide alternate probe logic in the public source tree. Outbound traffic uses TLS; frames are signed with Ed25519 so the server can drop forged uploads.

## Where to read the code

| Area | Path |
|------|------|
| Main binary | `cmd/963causal-agent/` |
| Enroll and session handling | `internal/license/`, `internal/payload/`, `internal/identity/` |
| Wire format | `proto/agent.proto` and call sites under `cmd/` and `internal/` |
| Probes (userspace and optional eBPF) | `internal/probe/`, `internal/sentinel/` |
| Packaging and install helper | `packaging/`, `scripts/install-agent-from-url.sh` |

Compare release tarballs to git tags, rebuild with `make release`, and check hashes against published assets if you need a reproducible path.

## Security (short)

Keys used to sign frames live on the host (`keystore_path` in config). Traffic uses HTTPS plus signatures on frames. Probe material decrypts only after enroll; session material is handled as described in `internal/payload/session.go`. For a threat oriented writeup see `redteam/THREAT-MODEL.md`. The `cmd/redteam/` tools are for lab use, not part of a normal install.

## Install a release binary

Your operator gives you a download URL and a license key. Example:

```bash
sudo CAUSAL_DOWNLOAD_URL="https://github.com/963s/963causal-agent-public/releases/download/<tag>/963causal-agent_linux_amd64.tar.gz" \
  bash scripts/install-agent-from-url.sh
```

Then configure `/etc/963causal/agent.yaml`, for example:

```yaml
control_plane_url: "https://your-control-plane.example"
license_key: "<from your operator>"
keystore_path: "/var/lib/963causal/host.key"
log_level: "info"
```

If you ship the full packaging layout beside `packaging/install.sh`, that script walks through a fuller setup.

## Build from source

Use the Go version listed in `go.mod`.

```bash
git clone https://github.com/963s/963causal-agent-public.git
cd 963causal-agent-public
make release
```

Single target example:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/963causal-agent ./cmd/963causal-agent
```

Run:

```bash
./bin/963causal-agent -config /path/to/agent.yaml
```

## Check a Causal ID or certificate

After enroll the agent logs your **Causal ID** (same value stored server-side). End users check sealed artefacts on the public portal:

**https://963causal.com/verify**

Paste the ID or open a link such as `https://963causal.com/verify?cid=CID-963-…`. The platform runs PAL and CUSUM gates, attaches a **drand** temporal anchor when available, wraps evidence in **COSE Sign1**, and offers a dark **forensic PDF** plus raw CBOR. Insurance-oriented **EAR** CBOR files from the operator dashboard can be checked under the same page (upload flow).

Independent CLI verification of PDF payloads may be added in a future agent release; today the authoritative path is the portal plus published verifier keys your operator documents.

## Hygiene of this tree

This repo starts from a clean git history. It should not contain `.env` files, host keys, or PEM material. Tests may use `127.0.0.1`; that is normal loopback and not a production endpoint.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contact

Product and support links: [963causal.com](https://963causal.com).
