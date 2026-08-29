#!/usr/bin/env bash
#
# cloak installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Cloak/main/install.sh | bash
#
# What it does:
#   1. Detects your device's CPU architecture.
#   2. Downloads the matching prebuilt zip from the latest GitHub Release
#      (via GitHub's stable "latest/download/<name>" URL -- always points
#      at whatever the current latest release is, no version-guessing).
#   3. Extracts it into ~/cloak/ and makes the three tools executable.
#   4. If the architecture isn't one of the ones we prebuild for, falls
#      back to downloading the plain .c source files and compiling them
#      locally with gcc/clang -- so this works even on an architecture
#      we didn't anticipate, as long as a C compiler is available.

set -e

REPO="SPARKY-CR/Cloak"
INSTALL_DIR="$HOME/cloak"
RAW_BASE="https://raw.githubusercontent.com/$REPO/main"
RELEASE_BASE="https://github.com/$REPO/releases/latest/download"

echo "cloak installer"
echo "----------------"

# ---------------------------------------------------------------
# Step 1: figure out which architecture we're on
# ---------------------------------------------------------------

MACHINE="$(uname -m)"
case "$MACHINE" in
    aarch64|arm64)
        ARCH="arm64-v8a"
        ;;
    armv7l|armv8l|armv7*)
        ARCH="armeabi-v7a"
        ;;
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    *)
        ARCH="unknown"
        ;;
esac

echo "detected architecture: $MACHINE -> $ARCH"

mkdir -p "$INSTALL_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------
# Step 2: try the prebuilt zip for this architecture
# ---------------------------------------------------------------

install_from_zip() {
    local zip_name="cloak-${ARCH}.zip"
    local url="$RELEASE_BASE/$zip_name"

    echo "downloading $zip_name ..."
    if ! curl -fsSL "$url" -o "$TMP_DIR/$zip_name" 2>/dev/null; then
        return 1
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        echo "error: 'unzip' is required but not installed."
        echo "run: pkg install unzip   (Termux)   or   apt install unzip   (Linux)"
        return 1
    fi

    unzip -oq "$TMP_DIR/$zip_name" -d "$TMP_DIR/extracted"
    cp "$TMP_DIR/extracted/cloak" "$TMP_DIR/extracted/cloakscan" "$TMP_DIR/extracted/cloaklinks" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/cloak" "$INSTALL_DIR/cloakscan" "$INSTALL_DIR/cloaklinks"
    return 0
}

# ---------------------------------------------------------------
# Step 3: fallback -- fetch source and compile locally
# ---------------------------------------------------------------

install_from_source() {
    echo "no prebuilt binary available for this architecture -- building from source instead."

    if ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        echo "error: no C compiler found."
        echo "run: pkg install clang   (Termux)   or   apt install gcc   (Linux)"
        exit 1
    fi
    CC="gcc"
    command -v gcc >/dev/null 2>&1 || CC="clang"

    for f in cloak.c cloakscan.c cloaklinks.c; do
        echo "downloading $f ..."
        curl -fsSL "$RAW_BASE/$f" -o "$TMP_DIR/$f"
    done

    echo "compiling with $CC ..."
    "$CC" -O2 -Wall -o "$INSTALL_DIR/cloak" "$TMP_DIR/cloak.c" -lpthread
    "$CC" -O2 -Wall -o "$INSTALL_DIR/cloakscan" "$TMP_DIR/cloakscan.c" -lpthread
    "$CC" -O2 -Wall -o "$INSTALL_DIR/cloaklinks" "$TMP_DIR/cloaklinks.c" -lpthread
}

# ---------------------------------------------------------------
# Run it
# ---------------------------------------------------------------

if [ "$ARCH" != "unknown" ] && install_from_zip; then
    echo "installed prebuilt binaries for $ARCH."
else
    install_from_source
fi

echo ""
echo "done. cloak, cloakscan, and cloaklinks are in $INSTALL_DIR"
echo ""
echo "next steps:"
echo "  cd ~/cloak"
echo "  ./cloak          # first run writes a starter cloak.conf"
