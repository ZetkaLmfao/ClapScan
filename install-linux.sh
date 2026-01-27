#!/bin/bash
# Installation script for ClapScan on Linux

set -e

echo "Installing ClapScan..."

# Build release version
cargo build --release

# Create directories
mkdir -p ~/.local/bin
mkdir -p ~/.local/share/applications
mkdir -p ~/.local/share/icons/hicolor/256x256/apps

# Copy executable
cp target/release/clapscan ~/.local/bin/
chmod +x ~/.local/bin/clapscan

# Convert .ico to .png for Linux (requires ImageMagick)
if command -v convert &> /dev/null; then
    convert src/logo.ico ~/.local/share/icons/hicolor/256x256/apps/clapscan.png
    echo "Icon installed"
else
    echo "Warning: ImageMagick not found. Icon not installed."
    echo "Install with: sudo apt install imagemagick (Ubuntu/Debian)"
    echo "or: sudo dnf install ImageMagick (Fedora)"
fi

# Install .desktop file
cp clapscan.desktop ~/.local/share/applications/

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database ~/.local/share/applications/
fi

echo "ClapScan installed successfully!"
echo "You can now launch it from your application menu or run: clapscan"
