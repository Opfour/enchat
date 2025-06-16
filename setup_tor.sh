#!/bin/bash

# --- Helper Functions ---
echo_info() { echo "[INFO] $1"; }
echo_success() { echo "[SUCCESS] $1"; }
echo_warn() { echo "[WARNING] $1"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# --- OS Detection ---
OS="$(uname -s)"
case "$OS" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*|MINGW*) MACHINE=Windows;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo_info "Starting Tor setup script..."
echo_info "Detected Operating System: $MACHINE"

if command_exists tor; then
    echo_success "Tor is already installed."
    echo_info "You can now try using enchat with the --tor flag."
    exit 0
fi

echo_warn "Tor is not installed."

case "$MACHINE" in
    Linux)
        echo_info "Instructions for installing Tor on Linux:"
        if command_exists apt-get; then
            echo "  For Debian/Ubuntu-based systems, run:"
            echo "    sudo apt update"
            echo "    sudo apt install tor -y"
        elif command_exists yum; then
            echo "  For Fedora/CentOS-based systems, you may need to set up the Tor repository first."
            echo "  Please see: https://support.torproject.org/rpm/"
            echo "  Then run: sudo yum install tor"
        elif command_exists pacman; then
            echo "  For Arch Linux-based systems, run:"
            echo "    sudo pacman -S tor"
        else
            echo_warn "Could not detect a common package manager (apt, yum, pacman)."
            echo_info "Please install Tor using your distribution's package manager."
        fi
        ;;
    Mac)
        echo_info "Instructions for installing Tor on macOS:"
        if command_exists brew; then
            echo "  Using Homebrew (recommended):"
            echo "    brew install tor"
        else
            echo_warn "Homebrew not found."
            echo_info "Please install Homebrew from https://brew.sh/ or download Tor from the official site:"
            echo "  https://www.torproject.org/download/"
        fi
        ;;
    Windows)
        echo_info "Instructions for installing Tor on Windows:"
        echo "  1. Download the Tor Expert Bundle from the official Tor website:"
        echo "     https://www.torproject.org/download/tor/"
        echo "  2. Extract the contents to a folder, for example C:\tor"
        echo "  3. Open a command prompt and navigate into the 'Tor' subdirectory."
        echo "  4. Run 'tor.exe' to start the Tor service."
        echo_warn "This script cannot automate the installation on Windows."
        ;;
    *)
        echo_warn "Unsupported operating system: $OS"
        echo_info "Please visit the Tor Project website for installation instructions:"
        echo "  https://www.torproject.org/download/"
        ;;
esac

echo_info "\nAfter installation, make sure the Tor service is running before using it with enchat."
echo_success "Script finished." 
