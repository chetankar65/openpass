#!/usr/bin/env bash
# Installs what openpass needs to build, builds it, and wires up the browser
# extension.
#
# Missing tools are installed without sudo: Go goes into .tools/ inside this
# checkout, and the Xcode Command Line Tools come from Apple's own installer.
# Steps that need a human — loading the unpacked extension, approving it — are
# printed rather than attempted, because neither can be done from a shell.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
BIN="$ROOT/bin"
TOOLS="$ROOT/.tools"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
die() { printf '\033[31merror: %s\033[0m\n' "$1" >&2; exit 1; }

EXT_ID="${1:-}"
OS="$(uname -s)"

# version_ge A B: true if dotted version A >= B.
version_ge() {
  local IFS=.
  local -a a=($1) b=($2)
  local i
  for i in 0 1 2; do
    local x="${a[i]:-0}" y="${b[i]:-0}"
    if ((10#$x > 10#$y)); then return 0; fi
    if ((10#$x < 10#$y)); then return 1; fi
  done
  return 0
}

# --- Xcode Command Line Tools (macOS) -----------------------------------------
# They provide swift for the menu bar app, and git and clang besides. On a
# fresh Mac /usr/bin/swift exists but is only a stub that offers to install
# them, so `command -v swift` proves nothing; xcode-select -p is the real test.

APP_OK=""
if [ "$OS" = Darwin ]; then
  step "Checking the Xcode Command Line Tools"
  if ! xcode-select -p >/dev/null 2>&1; then
    echo "Not installed. Opening Apple's installer — click Install in the dialog."
    xcode-select --install >/dev/null 2>&1 || true
    printf 'Waiting for the installation to finish'
    until xcode-select -p >/dev/null 2>&1; do
      printf '.'
      sleep 5
    done
    echo
  fi
  echo "found at $(xcode-select -p)"

  # Package.swift needs Swift 6 and macOS 14.
  MACOS_VERSION="$(sw_vers -productVersion)"
  SWIFT_VERSION="$(swift --version 2>/dev/null | sed -n 's/.*Swift version \([0-9.]*\).*/\1/p' | head -1)"
  if ! version_ge "$MACOS_VERSION" 14; then
    warn "The menu bar app needs macOS 14 or later (this is $MACOS_VERSION); skipping it."
  elif [ -z "$SWIFT_VERSION" ] || ! version_ge "$SWIFT_VERSION" 6; then
    warn "The menu bar app needs Swift 6 (found ${SWIFT_VERSION:-none}); skipping it."
    warn "Update the Command Line Tools in System Settings → General → Software Update,"
    warn "then run ./setup.sh again."
  else
    echo "Swift $SWIFT_VERSION"
    APP_OK=1
  fi
fi

# --- Go -----------------------------------------------------------------------
# Any Go new enough to satisfy go.mod will do, including an older one that
# fetches the right toolchain by itself (GOTOOLCHAIN=auto, the default).
# Otherwise the official release goes into .tools/go, checksum verified.

GO_WANT="$(sed -n 's/^go \([0-9.]*\)$/\1/p' go.mod)"

go_ok() {
  local v
  v="$(go env GOVERSION 2>/dev/null)" || return 1
  version_ge "${v#go}" "$GO_WANT"
}

install_go() {
  local os arch file url sum
  case "$OS" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) die "no Go download for $OS; install Go $GO_WANT+ from https://go.dev/dl/" ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64 | amd64) arch=amd64 ;;
    *) die "no Go download for $(uname -m); install Go $GO_WANT+ from https://go.dev/dl/" ;;
  esac
  file="go$GO_WANT.$os-$arch.tar.gz"
  url="https://dl.google.com/go/$file"

  echo "Downloading $file"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$file" "$url" || die "could not download $url"
  sum="$(curl -fsSL "$url.sha256")" || die "could not download the checksum for $file"
  if command -v sha256sum >/dev/null; then
    echo "$sum  $tmp/$file" | sha256sum -c - >/dev/null
  else
    echo "$sum  $tmp/$file" | shasum -a 256 -c - >/dev/null
  fi || die "checksum mismatch for $file"

  rm -rf "$TOOLS/go"
  mkdir -p "$TOOLS"
  tar -C "$TOOLS" -xzf "$tmp/$file"
  rm -rf "$tmp"
}

step "Checking Go"
# A Go installed by an earlier run comes first.
[ -x "$TOOLS/go/bin/go" ] && export PATH="$TOOLS/go/bin:$PATH"
if ! command -v go >/dev/null || ! go_ok; then
  echo "Go $GO_WANT or later is not installed; installing it into $TOOLS/go"
  install_go
  export PATH="$TOOLS/go/bin:$PATH"
  go_ok || die "the Go just installed does not work"
fi
go version

step "Building"
mkdir -p "$BIN"
go build -o "$BIN/openpass" ./cmd/openpass
go build -o "$BIN/openpassd" ./cmd/openpassd
go build -o "$BIN/openpass-bridge" ./cmd/openpass-bridge
echo "built into $BIN"

# On macOS the menu bar app replaces `openpass watch`, so it is part of a
# normal install rather than an extra step.
APP=""
if [ -n "$APP_OK" ]; then
  step "Building the menu bar app"
  # Quit a running copy so the new build is the one that starts.
  osascript -e 'quit app "OpenPass"' >/dev/null 2>&1 || true
  macos/build.sh --install
  APP="$HOME/Applications/OpenPass.app"
fi

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

if [ -n "$APP" ]; then
  step "Starting the menu bar app"
  open "$APP"
  cat <<EOF
Look for the lock in your menu bar. It shows a pairing code; approve it with:

  $BIN/openpass client approve XXXX-XXXX

"Launch at login" is in its settings menu.
EOF
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
Restart your browser, open the openpass extension, and run the approve
command it shows you:

  $BIN/openpass client approve XXXX-XXXX

EOF
if [ -z "$APP" ]; then
  cat <<EOF
Then leave this running whenever you want the extension to fill passwords.
It is what asks you before any password is handed over:

  $BIN/openpass watch

EOF
fi
cat <<EOF
Then: click a field on any login page, click the openpass icon, pick the entry.

EOF
bold "Add $BIN to your PATH to drop the ./bin/ prefix."
