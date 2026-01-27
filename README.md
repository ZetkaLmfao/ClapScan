# ClapScan - Port Scanner

## Quick Start

### Windows

#### Method 1: Download and Run (Recommended):
1. Download `clapscan.exe` from [Releases](https://github.com/SEU_USER/ClapScan/releases)
2. Use: `.\clapscan.exe 127.0.0.1 -p 80`

#### Method 2: Build from source:

**Prerequisites:**
- Rust 1.70+ (https://rustup.rs/)
- C++ build tools with SDK Windows 10/11

```bash
# 1. Run build script
run build.bat

# 2. Run scanner
clapscan --help
```

### Linux

#### Installation:

```bash
# Install dependencies (Ubuntu/Debian/Kali)
sudo apt install build-essential pkg-config libgtk-3-dev libssl-dev

# Install dependencies (Fedora)
sudo dnf install gcc gtk3-devel openssl-devel

# Run installation script
chmod +x install-linux.sh
./install-linux.sh
```

After installation, launch from application menu or run `clapscan` in terminal.

# Exemples 

```bash
clapscan google.com -p 80,443
clapscan 192.168.1.1 -p 1-1000 -c 500
clapscan --help