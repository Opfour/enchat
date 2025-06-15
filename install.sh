#!/bin/bash

set -e

# --- Configuration ---
INSTALL_DIR="$HOME/.enchat_app"
SOURCE_DIR=$(pwd)
EXECUTABLE_NAME="enchat"
VENV_DIR="$INSTALL_DIR/venv"

# --- Helper Functions ---
echo_info() { echo -e "\033[34m[INFO]\033[0m $1"; }
echo_success() { echo -e "\033[32m[SUCCESS]\033[0m $1"; }
echo_error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

# --- Main Script ---

# 1. Check Dependencies
echo_info "Checking for dependencies (python3)..."
if ! command_exists python3; then
    echo_error "python3 is not installed. Please install it to continue."
fi
echo_success "Dependencies found."

# 2. Setup application directory and virtual environment
echo_info "Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$VENV_DIR"
if [ $? -ne 0 ]; then
    echo_error "Failed to create a virtual environment."
fi
echo_success "Virtual environment created."

# 3. Copy application files
echo_info "Copying application files..."
cp -r "$SOURCE_DIR/enchat.py" "$SOURCE_DIR/enchat_lib" "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
if [ $? -ne 0 ]; then
    echo_error "Failed to copy application files."
fi
echo_success "Application files copied."

# 4. Install Python packages into the virtual environment
echo_info "Installing required Python packages into the virtual environment..."
if ! "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"; then
    echo_error "Failed to install Python packages."
fi
echo_success "Python packages installed."

# 5. Find a suitable directory in PATH for the executable
echo_info "Finding a suitable installation path for the executable..."
if [[ -d "/usr/local/bin" ]] && [[ -w "/usr/local/bin" ]]; then
    BIN_DIR="/usr/local/bin"
elif [[ -d "$HOME/.local/bin" ]] && [[ -w "$HOME/.local/bin" ]]; then
    BIN_DIR="$HOME/.local/bin"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
         echo -e "\033[33m[WARNING]\033[0m Your PATH does not seem to include $HOME/.local/bin. You may need to add it to run 'enchat'."
         echo -e "\033[33mAdd 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your ~/.bashrc or ~/.zshrc\033[0m"
    fi
else
    echo_error "Could not find a writable directory in your PATH. Please create and add ~/.local/bin to your PATH, or run this script with sudo."
fi
echo_info "Will install executable to $BIN_DIR"

# 6. Create the launcher script
LAUNCHER_PATH="$BIN_DIR/$EXECUTABLE_NAME"
echo_info "Creating launcher script at $LAUNCHER_PATH..."

cat > "$LAUNCHER_PATH" << EOF
#!/bin/bash
# Launcher for Enchat. Executes the application from its virtual environment.

APP_DIR="$INSTALL_DIR"
VENV_PYTHON="$VENV_DIR/bin/python"

# Check if the application directory exists
if [ ! -f "\$VENV_PYTHON" ]; then
    echo "Error: Enchat installation is corrupt. Python executable not found in venv." >&2
    exit 1
fi

# Run the python script from its directory using the venv python
"\$VENV_PYTHON" "\$APP_DIR/enchat.py" "\$@"
EOF

if [ $? -ne 0 ]; then
    echo_error "Failed to create launcher script."
fi

# 7. Make launcher executable
echo_info "Making launcher executable..."
chmod +x "$LAUNCHER_PATH"
if [ $? -ne 0 ]; then
    echo_error "Failed to make launcher executable. You might need to run 'chmod +x $LAUNCHER_PATH' manually."
fi

echo_success "Installation complete!"
echo_info "You can now run enchat by typing 'enchat' in your terminal."
echo_info "To uninstall, run the uninstall.sh script." 