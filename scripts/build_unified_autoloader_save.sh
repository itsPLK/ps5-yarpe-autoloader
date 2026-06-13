#!/usr/bin/env bash
# Script to build Yarpe save with the unified autoloader

set -euo pipefail

# Ensure we are in the project root
cd "$(dirname "$0")/.."

AUTOLOAD_DIR="yarpe_autoload"
mkdir -p "$AUTOLOAD_DIR"
mkdir -p "payloads"

AUTOLOADER_VERSION="1.0"
SHORT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
echo "$AUTOLOADER_VERSION-$SHORT_HASH" > "$AUTOLOAD_DIR/version.txt"
echo "Building Autoloader v${AUTOLOADER_VERSION}-${SHORT_HASH}..."

echo "Checking for curl..."
if ! command -v curl &> /dev/null; then
    echo "Error: curl is required to download dependencies." >&2
    exit 1
fi

echo "Fetching latest release URL for ps5-unified-autoloader..."
AUTOLOADER_RELEASE_JSON=$(curl -s https://api.github.com/repos/itsPLK/ps5-unified-autoloader/releases/latest)
AUTOLOADER_URL=$(echo "$AUTOLOADER_RELEASE_JSON" | grep -o 'https://github.com/itsPLK/ps5-unified-autoloader/releases/download/[^"]*\.elf' | head -n 1)
if [ -z "$AUTOLOADER_URL" ]; then
    echo "Error: Could not retrieve latest release URL for ps5-unified-autoloader." >&2
    exit 1
fi

AUTOLOADER_FILE="ps5-unified-autoloader.elf"

# Clean old dependency files
rm -f "$AUTOLOAD_DIR/ps5-unified-autoloader*.elf"

# Download asset
echo "Downloading $AUTOLOADER_URL to $AUTOLOAD_DIR/$AUTOLOADER_FILE..."
curl -L -o "$AUTOLOAD_DIR/$AUTOLOADER_FILE" "$AUTOLOADER_URL"

echo "Setting up payload dependencies in $AUTOLOAD_DIR..."
cp payloads/lapse.py "$AUTOLOAD_DIR/lapse.py" 2>/dev/null || echo "Warning: lapse.py not found in payloads/"
cp payloads/elf_loader.py "$AUTOLOAD_DIR/elf_loader.py" 2>/dev/null || echo "Warning: elf_loader.py not found in payloads/"

echo "Generating autoload.txt..."
cat <<EOF > "$AUTOLOAD_DIR/autoload.txt"
kexp_dispatch.py
ps5-unified-autoloader.elf
EOF

echo "Building save file..."
python3 pack_savegame.py

ZIP_NAME="ps5-yarpe-autoloader-v${AUTOLOADER_VERSION}-${SHORT_HASH}-savedata.zip"
mv save.zip "$ZIP_NAME"

echo ""
echo "=========================================================="
echo "Save generated as $ZIP_NAME"
echo "Please unzip $ZIP_NAME and drag-and-drop its contents into"
echo "garlic-savemgr on your PS5 (as per Yarpe's PS5 instructions)."
echo "=========================================================="
