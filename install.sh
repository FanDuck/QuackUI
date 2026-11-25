#!/usr/bin/env bash
# QuackUI One-Click Installer (Debian / Ubuntu)
# Author: FanDuck
set -e

INSTALL_DIR="/opt/quackui"
PORT="${QUACKUI_PORT:-8088}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo bash install.sh)."
  exit 1
fi

echo "==> Installing dependencies (python3, qrencode, curl, openssl)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 qrencode curl openssl >/dev/null

if ! command -v xray >/dev/null 2>&1; then
  echo "==> Installing Xray-core..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null
fi

echo "==> Setting up QuackUI in ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/web"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/app.py" ] && [ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]; then
  cp "${SCRIPT_DIR}/app.py" "${INSTALL_DIR}/app.py"
  cp "${SCRIPT_DIR}/web/login.html" "${INSTALL_DIR}/web/login.html"
  cp "${SCRIPT_DIR}/web/index.html" "${INSTALL_DIR}/web/index.html"
fi
chmod 700 "${INSTALL_DIR}/app.py"

if [ ! -f "${INSTALL_DIR}/config.json" ]; then
  PANEL_PW="${QUACKUI_PASS:-$(openssl rand -base64 12 | tr -d '/+=' | head -c 14)}"
  python3 - "${INSTALL_DIR}/config.json" "${PORT}" "${PANEL_PW}" <<'PY'
import hashlib, json, os, secrets, sys
cfg_path, port, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3]
salt = secrets.token_hex(16)
h = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 100000).hex()
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump({"host": "127.0.0.1", "port": port, "salt": salt, "password_hash": h}, f, indent=2)
os.chmod(cfg_path, 0o600)
PY
  echo "==> Initial password generated: ${PANEL_PW}"
fi

cat > /etc/systemd/system/quackui.service <<EOF
[Unit]
Description=QuackUI - Lightweight Local-First Xray Panel by FanDuck
After=network-online.target xray.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now quackui >/dev/null 2>&1
systemctl restart quackui

echo ""
echo "=========================================="
echo " QuackUI installed and running!"
echo " Local bind : http://127.0.0.1:${PORT}"
echo " Tunnel cmd : ssh -N -L ${PORT}:127.0.0.1:${PORT} root@YOUR_SERVER_IP"
echo "=========================================="
