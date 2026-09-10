#!/usr/bin/env bash
# Install the hidden relay bridge as a systemd service on a Raspberry Pi
# (or any systemd host). Run from a checkout of this repository:
#
#   sudo ./deploy/install.sh
#
# Re-running it upgrades the code in place and leaves the config alone.
set -euo pipefail

PREFIX="${PREFIX:-/opt/hidden-relay-bridge}"
CONFIG_DIR="${CONFIG_DIR:-/etc/hidden-relay-bridge}"
SERVICE_USER="${SERVICE_USER:-hiddenrelay}"
UNIT_NAME="hidden-relay-bridge.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script needs root: sudo $0" >&2
  exit 1
fi

echo "==> Installing build prerequisites"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-dev build-essential libsecp256k1-dev
fi

echo "==> Creating service user '${SERVICE_USER}'"
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${PREFIX}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "==> Installing code into ${PREFIX}"
mkdir -p "${PREFIX}"
cp -r "${SOURCE_DIR}/src" "${SOURCE_DIR}/pyproject.toml" "${SOURCE_DIR}/README.md" "${PREFIX}/"
cp -r "${SOURCE_DIR}/tools" "${PREFIX}/" 2>/dev/null || true

if [[ ! -d "${PREFIX}/venv" ]]; then
  python3 -m venv "${PREFIX}/venv"
fi
"${PREFIX}/venv/bin/pip" install --quiet --upgrade pip
"${PREFIX}/venv/bin/pip" install --quiet "${PREFIX}"

echo "==> Preparing ${CONFIG_DIR}"
mkdir -p "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
  cp "${SOURCE_DIR}/config.example.toml" "${CONFIG_DIR}/config.toml"
  echo "    Wrote ${CONFIG_DIR}/config.toml from the example. Edit it before starting."
  echo "    Generate an identity with: ${PREFIX}/venv/bin/hidden-relay-bridge keygen"
else
  echo "    Keeping the existing ${CONFIG_DIR}/config.toml"
fi
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${CONFIG_DIR}" "${PREFIX}"
chmod 750 "${CONFIG_DIR}"
chmod 640 "${CONFIG_DIR}/config.toml"

echo "==> Installing ${UNIT_NAME}"
install -m 0644 "${SOURCE_DIR}/deploy/${UNIT_NAME}" "/etc/systemd/system/${UNIT_NAME}"
systemctl daemon-reload
systemctl enable "${UNIT_NAME}"

cat <<EOF

Installed.

  1. Edit    ${CONFIG_DIR}/config.toml
  2. Verify  sudo -u ${SERVICE_USER} ${PREFIX}/venv/bin/hidden-relay-bridge check --config ${CONFIG_DIR}/config.toml
  3. Start   sudo systemctl start ${UNIT_NAME}
  4. Watch   journalctl -u ${UNIT_NAME} -f

EOF
