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

# --- Dependency Check & Auto-Install ---
echo_info "Checking for Python 3..."
if ! command_exists python3; then
    echo_error "python3 is not installed. Please install it manually."
fi

echo_info "Checking for python3-venv module..."
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo_info "python3-venv not found. Attempting to install it..."

    if command_exists apt; then
        sudo apt update && sudo apt install -y python3-venv
    elif command_exists dnf; then
        sudo dnf install -y python3-venv
    elif command_exists pacman; then
        sudo pacman -Sy --noconfirm python-virtualenv
    else
        echo_error "Could not install python3-venv automatically. Please install it manually for your system."
    fi
fi
echo_success "Python and virtual environment support verified."

# --- Setup application directory and virtual environment ---
echo_info "Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$VENV_DIR"
if [ $? -ne 0 ]; then
    echo_error "Failed to create a virtual environment."
fi
echo_success "Virtual environment created."

# --- Copy application files ---
echo_info "Copying application files..."
cp -r "$SOURCE_DIR/enchat.py" "$SOURCE_DIR/enchat_lib" "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
if [ $? -ne 0 ]; then
    echo_error "Failed to copy application files."
fi
echo_success "Application files copied."

# --- Install Python packages into the virtual environment ---
echo_info "Installing required Python packages into the virtual environment..."
if ! "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"; then
    echo_error "Failed to install Python packages."
fi
echo_success "Python packages installed."

# --- Find or create a suitable directory in PATH for the executable ---
echo_info "Finding a suitable installation path for the executable..."
BIN_DIR=""

if [[ -d "$HOME/.local/bin" ]] && [[ -w "$HOME/.local/bin" ]]; then
    BIN_DIR="$HOME/.local/bin"
elif [[ -d "/usr/local/bin" ]] && [[ -w "/usr/local/bin" ]]; then
    BIN_DIR="/usr/local/bin"
fi

if [ -z "$BIN_DIR" ]; then
    echo_info "~/.local/bin not found or not writable. Creating it..."
    mkdir -p "$HOME/.local/bin"
    if [ $? -ne 0 ]; then
        echo_error "Failed to create $HOME/.local/bin. Please check permissions."
    fi
    BIN_DIR="$HOME/.local/bin"
fi

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
     echo -e "\033[33m[WARNING]\033[0m Your PATH does not seem to include $BIN_DIR."
     echo -e "\033[33m         To run 'enchat' from anywhere, you may need to add it to your shell's config file."
     echo -e "\033[33m         Add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your ~/.zshrc or ~/.bashrc and restart your terminal.\033[0m"
fi

echo_info "Will install executable to $BIN_DIR"

# --- Create the launcher script ---
LAUNCHER_PATH="$BIN_DIR/$EXECUTABLE_NAME"
echo_info "Creating launcher script at $LAUNCHER_PATH..."

cat > "$LAUNCHER_PATH" << EOF
#!/bin/bash
# Launcher for Enchat. Executes the application from its virtual environment.

APP_DIR="$INSTALL_DIR"
VENV_PYTHON="$VENV_DIR/bin/python"

if [ ! -f "\$VENV_PYTHON" ]; then
    echo "Error: Enchat installation is corrupt. Python executable not found in venv." >&2
    exit 1
fi

"\$VENV_PYTHON" "\$APP_DIR/enchat.py" "\$@"
EOF

if [ $? -ne 0 ]; then
    echo_error "Failed to create launcher script."
fi

# --- Make launcher executable ---
echo_info "Making launcher executable..."
chmod +x "$LAUNCHER_PATH"
if [ $? -ne 0 ]; then
    echo_error "Failed to make launcher executable. You might need to run 'chmod +x $LAUNCHER_PATH' manually."
fi

# --- Finish ---
echo_success "Installation complete!"
echo_info "You can now run enchat by typing 'enchat' in your terminal."
echo_info "To uninstall, run the uninstall.sh script."