#!/usr/bin/env bash
# Registers openpass-bridge as a Chrome native messaging host.
#
# Chrome will only launch the bridge for the extension IDs listed in the
# manifest this writes, which is what stops any other extension reaching your
# vault. That check is the browser's, not ours.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <extension-id> [path-to-openpass-bridge]

Find the extension id at chrome://extensions with Developer mode on.
EOF
  exit 1
}

[ $# -ge 1 ] || usage

EXT_ID="$1"
BRIDGE="${2:-$(command -v openpass-bridge || true)}"

if [ -z "$BRIDGE" ] || [ ! -x "$BRIDGE" ]; then
  echo "error: openpass-bridge not found. Build it with:" >&2
  echo "  go build -o bin/openpass-bridge ./cmd/openpass-bridge" >&2
  echo "then pass its path as the second argument." >&2
  exit 1
fi

BRIDGE="$(cd "$(dirname "$BRIDGE")" && pwd)/$(basename "$BRIDGE")"

case "$(uname -s)" in
  Darwin)
    DIRS=(
      "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
      "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
      "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    )
    ;;
  Linux)
    DIRS=(
      "$HOME/.config/google-chrome/NativeMessagingHosts"
      "$HOME/.config/chromium/NativeMessagingHosts"
    )
    ;;
  *)
    echo "error: unsupported platform $(uname -s)" >&2
    exit 1
    ;;
esac

MANIFEST=$(cat <<EOF
{
  "name": "com.openpass.bridge",
  "description": "openpass native bridge",
  "path": "$BRIDGE",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
)

INSTALLED=0
for dir in "${DIRS[@]}"; do
  parent="$(dirname "$dir")"
  [ -d "$parent" ] || continue

  mkdir -p "$dir"
  printf '%s\n' "$MANIFEST" > "$dir/com.openpass.bridge.json"
  chmod 0644 "$dir/com.openpass.bridge.json"
  echo "installed: $dir/com.openpass.bridge.json"
  INSTALLED=1
done

if [ "$INSTALLED" -eq 0 ]; then
  echo "error: no Chrome-family browser profile found" >&2
  exit 1
fi

echo
echo "bridge: $BRIDGE"
echo "extension: $EXT_ID"
echo
echo "Restart the browser, then open the extension and approve it with the"
echo "code it shows:  openpass client approve XXXX-XXXX"
