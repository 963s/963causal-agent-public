#!/usr/bin/env bash
# CAUSAL_963 agent installer. Requires root.
#
# Usage:
#   sudo ./install.sh --license EID-XXXXXXXX --server https://963causal.com
set -euo pipefail

LICENSE=""
SERVER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --license) LICENSE="$2"; shift 2;;
    --server)  SERVER="$2";  shift 2;;
    *) echo "unknown flag: $1" >&2; exit 2;;
  esac
done

[[ -z "$LICENSE" || -z "$SERVER" ]] && {
  echo "usage: sudo $0 --license CSL-... --server https://963causal.com" >&2
  exit 2
}

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

BIN_SRC="$(dirname "$0")/../bin/963causal-agent"
[[ -x "$BIN_SRC" ]] || { echo "binary not found at $BIN_SRC" >&2; exit 3; }

id -u 963causal &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin 963causal

install -m 0755 -o root -g root "$BIN_SRC" /usr/bin/963causal-agent
install -d -m 0750 -o 963causal -g 963causal /var/lib/963causal
install -d -m 0755 -o root    -g root    /etc/963causal

cat > /etc/963causal/agent.yaml <<EOF
control_plane_url: "$SERVER"
license_key: "$LICENSE"
keystore_path: "/var/lib/963causal/host.key"
log_level: "info"
EOF
chown root:963causal /etc/963causal/agent.yaml
chmod 0640 /etc/963causal/agent.yaml

install -m 0644 "$(dirname "$0")/963causal-agent.service" /etc/systemd/system/963causal-agent.service

systemctl daemon-reload
systemctl enable --now 963causal-agent.service
sleep 2
systemctl --no-pager status 963causal-agent.service | head -20

echo
echo "963causal-agent installed. Journal: journalctl -u 963causal-agent -f"
