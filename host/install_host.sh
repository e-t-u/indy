#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_PY="${SCRIPT_DIR}/indy_host.py"
MANIFEST_SRC="${SCRIPT_DIR}/com.etu.indy.json"

chmod +x "${HOST_PY}"

# Target NativeMessagingHosts directories for Chrome, ChromeDev Flatpak, and Chromium
TARGET_DIRS=(
  "${HOME}/.config/google-chrome/NativeMessagingHosts"
  "${HOME}/.config/google-chrome-unstable/NativeMessagingHosts"
  "${HOME}/.config/chromium/NativeMessagingHosts"
  "${HOME}/.var/app/com.google.ChromeDev/config/google-chrome/NativeMessagingHosts"
  "${HOME}/.var/app/com.google.ChromeDev/config/google-chrome-unstable/NativeMessagingHosts"
)

for dir in "${TARGET_DIRS[@]}"; do
  mkdir -p "${dir}"
  python3 -c "
import json, sys
with open('${MANIFEST_SRC}', 'r') as f:
    data = json.load(f)
data['path'] = '${HOST_PY}'
with open('${dir}/com.etu.indy.json', 'w') as f:
    json.dump(data, f, indent=2)
"
  echo "Installed Native Messaging manifest -> ${dir}/com.etu.indy.json"
done

# Install and start systemd user daemon for HTTP bridge (127.0.0.1:7879)
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
mkdir -p "${SYSTEMD_USER_DIR}"
sed "s|HOST_PATH_PLACEHOLDER|${HOST_PY}|g" "${SCRIPT_DIR}/indy-daemon.service" > "${SYSTEMD_USER_DIR}/indy-daemon.service"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user daemon-reload || true
  systemctl --user enable --now indy-daemon.service || true
  echo "Enabled and started indy-daemon.service on http://127.0.0.1:7879"
fi
