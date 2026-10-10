#!/usr/bin/env bash
# Builds OpenPass.app, the menu bar app, with openpassd and openpass bundled
# next to its executable so it can start the daemon without anything on PATH.
#
#   macos/build.sh            build into macos/build/OpenPass.app
#   macos/build.sh --install  also copy it to ~/Applications
set -euo pipefail

cd "$(dirname "$0")"
MACOS="$(pwd)"
ROOT="$(cd .. && pwd)"
APP="$MACOS/build/OpenPass.app"

echo "==> Building the Go binaries"
mkdir -p "$ROOT/bin"
(cd "$ROOT" && go build -o bin/openpassd ./cmd/openpassd && go build -o bin/openpass ./cmd/openpass)

echo "==> Building the menu bar app"
swift build -c release --package-path "$MACOS"
BIN_DIR="$(swift build -c release --package-path "$MACOS" --show-bin-path)"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$MACOS/Info.plist" "$APP/Contents/Info.plist"
cp "$BIN_DIR/OpenPassMenu" "$APP/Contents/MacOS/OpenPassMenu"
cp "$ROOT/bin/openpassd" "$ROOT/bin/openpass" "$APP/Contents/MacOS/"

# Ad-hoc signing is enough to run locally and to register as a login item.
codesign --force --deep --sign - "$APP"

if [ "${1:-}" = "--install" ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/OpenPass.app"
  cp -R "$APP" "$HOME/Applications/"
  APP="$HOME/Applications/OpenPass.app"
  echo "installed to $APP"
fi

echo
echo "Run it with:  open \"$APP\""
