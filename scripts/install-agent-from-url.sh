#!/usr/bin/env bash
# Install 963causal-agent from an HTTPS tarball or direct binary URL (runs as root).
#
# Env:
#   CAUSAL_DOWNLOAD_URL — required; URL to gzipped tarball OR raw binary named 963causal-agent
#
# tarball layout (optional convenience):
#   963causal-agent          (chmod +x)
#   packaging/963causal-agent.service
#
# Example:
#   sudo CAUSAL_DOWNLOAD_URL=https://releases.example.com/963causal-agent_linux_amd64.tar.gz \
#        bash scripts/install-agent-from-url.sh
set -euo pipefail

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if [[ -z "${CAUSAL_DOWNLOAD_URL:-}" ]]; then
  echo "set CAUSAL_DOWNLOAD_URL to a tarball or binary URL" >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

echo "Downloading…"
curl -fsSL "$CAUSAL_DOWNLOAD_URL" -o "$tmpdir/payload"

mkdir -p /usr/local/bin /etc/systemd/system

if tar -tzf "$tmpdir/payload" >/dev/null 2>&1; then
  tar -xzf "$tmpdir/payload" -C "$tmpdir"
  bin="$(find "$tmpdir" -maxdepth 3 -type f \( -name 963causal-agent -o -name 963causal-agent-linux-* \) -perm /111 | head -1)"
  [[ -x "$bin" ]] || bin="$(find "$tmpdir" -maxdepth 3 -type f -name 963causal-agent-linux-* | head -1)"
else
  cp "$tmpdir/payload" "$tmpdir/963causal-agent"
  chmod +x "$tmpdir/963causal-agent"
  bin="$tmpdir/963causal-agent"
fi

[[ -n "${bin:-}" && -f "$bin" ]] || { echo "could not locate binary inside archive" >&2; exit 3; }

install -m 0755 "$bin" /usr/local/bin/963causal-agent

unit="$tmpdir/packaging/963causal-agent.service"
if [[ -f "$unit" ]]; then
  sed 's|^ExecStart=/usr/bin/963causal-agent|ExecStart=/usr/local/bin/963causal-agent|' "$unit" > /etc/systemd/system/963causal-agent.service
else
  cat > /etc/systemd/system/963causal-agent.service << 'UNIT'
[Unit]
Description=963causal Runtime Integrity Agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/963causal-agent -config /etc/963causal/agent.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
fi

echo "Installed /usr/local/bin/963causal-agent"
echo "Create /etc/963causal/agent.yaml then:"
echo "  systemctl daemon-reload && systemctl enable --now 963causal-agent"
