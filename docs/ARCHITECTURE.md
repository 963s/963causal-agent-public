# Architecture reference

The agent ships as one static binary.

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
   |    signed frames               |
   |------------------------------->|
   |                                |
   | 7. POST /api/agent/heartbeat   |
   |------------------------------->|
   |                                | revoke if grace expires
```

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

## Layout

```
cmd/963causal-agent/     entry point
internal/identity/       keys and storage
internal/license/        enroll client
internal/payload/        decrypt and session
internal/probe/          measurements
internal/histogram/      epoch histograms
internal/sculpture/      genotype side of sculpture pipeline
internal/config/         YAML
internal/daq/            witness and drand helpers
proto/                   protobuf
packaging/               systemd and install scripts
scripts/                 download and install helpers
```
