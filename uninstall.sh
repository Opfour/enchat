#!/bin/bash

# --- Configuration ---
INSTALL_DIR="$HOME/.enchat_app"
EXECUTABLE_NAME="enchat"
BIN_DIRS=("$HOME/bin" "$HOME/.local/bin" "/usr/local/bin")

# --- Helper Functions ---
echo_info() { echo -e "\033[34m[INFO]\033[0m $1"; }
echo_success() { echo -e "\033[32m[SUCCESS]\033[0m $1"; }
echo_warning() { echo -e "\033[33m[WARNING]\033[0m $1"; }

# --- Main Script ---
echo_info "Starting Enchat uninstallation..."

# 1. Find and remove the executable from common bin directories
LAUNCHER_REMOVED=false
for dir in "${BIN_DIRS[@]}"; do
    LAUNCHER_PATH="$dir/$EXECUTABLE_NAME"
    if [ -f "$LAUNCHER_PATH" ]; then
        echo_info "Removing executable at $LAUNCHER_PATH..."
        if rm "$LAUNCHER_PATH"; then
            echo_success "Executable removed."
            LAUNCHER_REMOVED=true
        else
            echo_warning "Failed to remove executable at $LAUNCHER_PATH. You may need to remove it manually (e.g., with sudo)."
        fi
    fi
done

if [ "$LAUNCHER_REMOVED" = false ]; then
    echo_info "Enchat executable not found in common paths. Skipping."
fi

# 2. Remove the installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo_info "Removing installation directory at $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    echo_success "Installation directory removed."
else
    echo_info "Installation directory not found. Skipping."
fi

echo_success "Uninstallation complete!" 