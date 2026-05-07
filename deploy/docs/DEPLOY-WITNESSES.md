# Deploying DAQ Witnesses (W7 Phase 2)

> **Audience:** the operator with Oracle Cloud (or equivalent) credentials.
> **Prerequisite:** W6 Phase 2 shipped and locally green; see BSL §13.3.
> **Outcome:** three witnesses, each on a different continent, attesting
> sensitive operations for the control plane, with no code running
> anywhere the sandbox cannot reach.

## 0. Why geographic diversity

Local witness processes (ids 9–13 on the control-plane host) share a
single failure domain: if the control-plane host is compromised, all
five "independent" signatures come from the same attacker. Moving the
witnesses to three separate cloud accounts, in three different
countries, breaks that correlation. A ticket is now cryptographic
evidence that the operation was endorsed by three independent
operators — not just three independent processes.

## 1. Shape of the target fleet

We pick three regions far enough apart that one backbone outage
cannot blackout all of them, and we pick providers such that no single
control-plane hijack can silently rewrite a witness:

| Role | Region | Provider (example) |
|------|--------|---------------------|
| witness-0 | Tokyo (ap-northeast-1)   | Oracle Cloud ARM "Always Free" |
| witness-1 | Frankfurt (eu-central-1) | Oracle Cloud ARM "Always Free" |
| witness-2 | São Paulo (sa-east-1)    | Oracle Cloud ARM "Always Free" |

Three continents ⇒ ≥ 150 ms inter-node latency, each served by a
different submarine-cable basin.

> We deliberately ship with `n=3, threshold=3` in Phase 2. The extra
> two local witnesses (ids 9–13) can be retired at roster rotation
> time; we keep the records so pre-rotation tickets stay verifiable.

## 2. Per-VM requirements

Minimum:

- Ubuntu 22.04 LTS or Debian 12, ARM64 or amd64.
- 1 vCPU, 1 GiB RAM, 10 GiB disk — a witness idles at < 10 MiB RSS.
- A stable public IPv4 address.
- TCP 17001 open **only** to the control-plane egress IP (locked
  down by the cloud security-group or UFW).

Strongly recommended (not required for MVP):

- A pinned domain name (`witness-00.daq.963causal.com`) so TLS can be
  layered in later without rewriting the roster.
- `unattended-upgrades` on for kernel / OpenSSH CVEs.

## 3. Provision flow (per witness)

Run these on your laptop / jump host, not on the VM:

```bash
cd ~/963causal-agent

# (a) If you have not yet rotated tokens for the new deployment,
# mint a fresh roster. Keep the old one — it stays verifiable for
# historical tickets.
bin/daq-seed \
  --dir   /tmp/daq-global \
  --n     3 \
  --threshold 3 \
  --base-port 17001 \
  --host      witness-%INDEX%.example.com \
  --overwrite \
  > /tmp/roster-global.json
# daq-seed prints one witness-per-line to stderr with the token
# fingerprint for easy cross-checking with the deployed value.

# (b) Ship the per-witness materials to each VM:
for i in 0 1 2; do
  IDX=$(printf "%02d" $i)
  HOST="witness-${IDX}.example.com"
  scp bin/963causal-witness                                  963causal@"$HOST":/tmp/
  scp deploy/systemd/963causal-witness@.service             963causal@"$HOST":/tmp/
  scp /tmp/daq-global/witness-${IDX}.key{,.token}         963causal@"$HOST":/tmp/
  scp deploy/scripts/install-witness.sh                   963causal@"$HOST":/tmp/
done
```

Then SSH into each VM and run the installer once:

```bash
ssh 963causal@witness-00.example.com 'sudo bash /tmp/install-witness.sh \
  --index 0 \
  --label tokyo \
  --addr 0.0.0.0:17001 \
  --key   /tmp/witness-00.key \
  --token /tmp/witness-00.key.token \
  --binary /tmp/963causal-witness \
  --unit-template /tmp/963causal-witness@.service \
  --allow-from <CONTROL_PLANE_EGRESS_IP>'
```

The installer:

- Creates the `963causal` system user, home, and log dir.
- Installs the binary to `/usr/local/bin/963causal-witness`.
- Drops BLS key (0600) + token (0400) under `/var/lib/963causal/daq/`.
- Renders `/etc/963causal/witness-${INDEX}.env` with the sharded
  config (address, key path, token path, chain pubkey — pinned to
  LoE fastnet).
- Enables + starts `963causal-witness@${INDEX}.service`.
- Opens the port in UFW only for the supplied control-plane IP,
  if UFW is active. If not, documents that the cloud security
  group is authoritative.

Systemd hardening inherited from the unit template: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp`,
`PrivateDevices`, `RestrictNamespaces`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`. A compromised witness binary
cannot load kernel modules, touch control groups, or spawn
non-service system calls.

## 4. Sanity-check each witness

From the control-plane host (or any allowlisted origin):

```bash
curl -sS https://witness-00.example.com:17001/daq/info | jq
#   { "witness_index":0, "label":"tokyo", "pubkey":"…", "drand_chain":"52db9ba…" }
```

Pubkey MUST match the `"pubkey"` field in `/tmp/roster-global.json` for
that index. If it does not, the witness is running with a different
BLS key than the roster thinks (the installer picked up the wrong
file); stop and redo step 3b.

A probe without a bearer token MUST return `HTTP 401 "missing bearer
token"`. Verify:

```bash
curl -sS -X POST -o /dev/null -w "HTTP %{http_code}\n" \
  https://witness-00.example.com:17001/daq/sign
#   HTTP 401
```

## 5. Rotate the active DAQ roster

On the control-plane host (or wherever Next.js lives):

```bash
# Copy the roster envelope over and rotate in one atomic
# transaction. --force-rotate is required because the previous
# roster already occupied label="default"; the script gives the
# old row a timestamped label and deactivates it.
scp /tmp/roster-global.json control-plane:/tmp/
ssh control-plane '
  cd /home/ubuntu/963causal-site && \
  npm run daq:seed-roster -- /tmp/roster-global.json \
    --label=v2-global --force-rotate
'
```

From now on every `executeDaq` will fan out to the three cloud
witnesses. Tickets issued against the old roster stay verifiable
(their `DaqTicket.rosterId` still points to the deactivated row).

## 6. Retire the local witnesses

After a day or two of green tickets on the new roster:

```bash
pm2 stop    963causal-witness-{1..5}
pm2 delete  963causal-witness-{1..5}
pm2 save
```

The keys under `/var/lib/963causal/daq/witness-0{0..4}.key` can be
archived or destroyed — nothing references them once the old roster
is deactivated.

## 7. Verifying the rotation end-to-end

- Hit `/hosts/<id>` in the dashboard: the DAQ card's roster grid
  shows the three remote URLs.
- Trigger a non-destructive DAQ round (e.g. delete a throwaway host
  you first create via `psql`) and watch the ticket land with
  `drand_round = (fresh)`, `participants = [0,1,2]`, and
  `durationMs < 2 s` (inter-continental latency dominates).
- Stop one witness (e.g. Tokyo) with `sudo systemctl stop
  963causal-witness@0` and retry the same operation: the ticket will
  fail (`only 2 of required 3 witnesses signed`) because k=3 of
  n=3 leaves no slack. Bring the witness back up or lower the
  threshold with another `--force-rotate`.

## 8. Ongoing operations

- **Logs.** `journalctl -u 963causal-witness@0 -f`.
- **Metrics.** The witness exposes no Prometheus endpoint yet; add
  one in a later phase if you need per-signature latency curves.
  Systemd's `TasksMax=32` + `MemoryMax=128M` are usually enough as
  health proxies.
- **Key rotation.** Re-run `daq-seed --overwrite` on the control
  plane, ship the new keys + tokens, and rotate the roster. Keep
  the deactivated row so pre-rotation tickets stay auditable.
- **Recovery from a single lost witness.** Redeploy to a fresh VM
  using the same roster index; the BLS key and token files are all
  the state a witness owns.

## 9. When Phase 2 is "done"

- 3 witnesses reachable from the control-plane egress IP, each
  returning `/daq/info` with the pubkey that matches the seeded
  roster row.
- The default/local roster is deactivated; `v2-global` is the
  active one.
- A live `host.delete` ticket (or any other DAQ-gated op) shows
  `participants: [0,1,2]` and `drand_round` within the last 10 s
  of wall-clock time on the control plane.

At that point the DAQ has cleared the "three independent countries,
three independent operators, one cryptographic signature" bar that
W7 was defined to deliver.
