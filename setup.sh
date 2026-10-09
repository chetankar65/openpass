#!/usr/bin/env bash
# Builds openpass and wires up the browser extension.
#
# Steps that need a human — loading the unpacked extension, approving it — are
# printed rather than attempted, because neither can be done from a shell.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
BIN="$ROOT/bin"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }

EXT_ID="${1:-}"

step "Checking Go"
if ! command -v go >/dev/null; then
  echo "error: Go is not installed. https://go.dev/dl/" >&2
  exit 1
fi
go version

step "Building"
mkdir -p "$BIN"
go build -o "$BIN/openpass" ./cmd/openpass
go build -o "$BIN/openpassd" ./cmd/openpassd
go build -o "$BIN/openpass-bridge" ./cmd/openpass-bridge
echo "built into $BIN"

# A daemon from a previous build keeps serving until it is stopped, and a new
# CLI cannot talk to it.
if pgrep -x openpassd >/dev/null 2>&1; then
  step "Stopping the previous daemon"
  pkill -x openpassd || true
  sleep 1
  echo "stopped; a new one starts on first use"
fi

step "Vault"
VAULT="$HOME/.openpass/vault.opv"
if [ -f "$VAULT" ]; then
  echo "already exists at $VAULT"
else
  echo "Creating a vault. Your master password cannot be recovered."
  echo
  "$BIN/openpass" init
fi

if [ -z "$EXT_ID" ]; then
  step "Load the extension"
  cat <<EOF
Do this in your browser, then come back:

  1. Open  chrome://extensions
  2. Turn on  Developer mode
  3. Click  Load unpacked  and choose:
       $ROOT/extension
  4. Copy the extension ID it shows

EOF
  read -r -p "Extension ID (or Enter to skip): " EXT_ID
fi

if [ -z "$EXT_ID" ]; then
  warn "Skipped. Finish later with:  ./setup.sh <extension-id>"
  exit 0
fi

step "Registering the native messaging host"
./extension/install-host.sh "$EXT_ID" "$BIN/openpass-bridge"

step "Almost done"
cat <<EOF
Two steps left, both in a terminal:

  1. Restart your browser, open the openpass extension, and run the
     approve command it shows you:

       $BIN/openpass client approve XXXX-XXXX

  2. Leave this running whenever you want the extension to fill passwords.
     It is what asks you before any password is handed over:

       $BIN/openpass watch

Then: click a field on any login page, click the openpass icon, pick the entry.

EOF
bold "Add $BIN to your PATH to drop the ./bin/ prefix."
