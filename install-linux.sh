#!/bin/bash
# Installation script for ClapScan on Linux

set -e

echo "Installing ClapScan..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo not found!"
    echo "Please install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "Then restart your terminal and run this script again."
    exit 1
fi

# Check for required dependencies
echo "Checking dependencies..."
if ! pkg-config --exists openssl; then
    echo "Error: OpenSSL development files not found!"
    echo "Please install them:"
    echo "  Ubuntu/Debian/Kali: sudo apt install libssl-dev pkg-config"
    echo "  Fedora: sudo dnf install openssl-devel pkg-config"
    exit 1
fi

# Build release version
echo "Building ClapScan..."
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
