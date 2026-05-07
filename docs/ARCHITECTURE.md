# Agent architecture (technical reference)

The runtime integrity agent ships as a single static binary.

## Identity-bound encryption handshake

963causal agents do not carry usable probe logic on disk. At install time the
binary contains only an encrypted payload. The decryption key is never
persisted; it is derived from a handshake with the control plane and
lives in RAM only.

```
 agent                               control plane
   |                                    |
   | 1. generate Ed25519(sign)          |
   |    generate X25519(kex)            |
   |    hw_fp = sha3(cpu|mem|machine-id)|
   |                                    |
   | 2. POST /api/agent/enroll          |
   |    {license, ed_pub, x_pub,        |
   |     hw_fp, hostname, os, ...}      |
   |----------------------------------->|
   |                                    | 3. validate license
   |                                    |    derive session_key =
   |                                    |      X25519(server_priv, x_pub)
   |                                    |      KDF(HKDF-SHA3)
   |                                    |    encrypt probe config with
   |                                    |      ChaCha20-Poly1305(session_key)
   |                                    |    store sha3(session_key) on host
   |                                    |
   |  4. {host_id, agent_token,         |
   |      server_x_pub,                 |
   |      encrypted_payload, nonce,     |
   |      heartbeat_interval, ...}      |
   |<-----------------------------------|
   |                                    |
   | 5. session_key = X25519(           |
   |      x_priv, server_x_pub)         |
   |      |> HKDF                       |
   |    probe_cfg = decrypt(            |
   |      encrypted_payload, nonce,     |
   |      session_key)  -- RAM only     |
   |    begin probing                   |
   |                                    |
   | 6. every frame_epoch_sec:          |
   |    POST /api/agent/frame           |
   |    body = Ed25519-signed Frame     |
   |----------------------------------->|
   |                                    |
   | 7. every heartbeat_interval_sec:   |
   |    POST /api/agent/heartbeat       |
   |----------------------------------->|
   |                                    | if grace expires: revoke
```

### Key properties

- **Local Ed25519 identity:** `internal/identity` generates/stores host signing keys (`keystore_path`); **the private half never leaves the host** except into RAM for signing—it is not transmitted to the control plane.
- **Signed telemetry:** Frames are `SignedFrame` (Ed25519 over `frameBlob`); heartbeats embed an Ed25519 signature over `(host_id || sequence || ts)`. TLS protects the circuit; payloads are protobuf + bearer `agent_token` after enroll.
- **Release builds:** `make release` emits static Linux binaries (`CGO_ENABLED=0`, trimmed). Install template: see `scripts/install-agent-from-url.sh`.
- **Control plane must distrust callers:** Servers must enforce valid license rows, cryptographic verification on ingest endpoints, and rate limiting against agent-shaped DoS floods.

### Additional properties

- The binary on disk never contains the probe logic in the clear.
- Copying the binary to another host buys nothing: the license is bound
  to `hw_fingerprint`, and the session key is re-derived per host.
- Network loss: after `grace_period_sec` without a heartbeat, the agent zeroes
  the session key in memory and halts probing until it can re-handshake.
- Server compromise: rotating the server keypair invalidates all live sessions
  on next heartbeat.

## Repository layout

```
cmd/963causal-agent/       main entrypoint
internal/identity/         Ed25519 + X25519 keypair generation & storage
internal/license/          handshake with control plane
internal/payload/          encrypted probe config loader
internal/probe/            measurement sources (userspace, optional eBPF)
internal/histogram/        HDR histogram epoch rotation
internal/sculpture/        vertices + genotype derivation
internal/config/           YAML config loader
internal/daq/              Distributed Attestation Quorum (witness / drand)
proto/                     wire format
packaging/                 systemd unit, installer
scripts/                   install helpers
```
