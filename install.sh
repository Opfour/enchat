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

# --- OS Detection ---
OS="$(uname -s)"
case "$OS" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*|MINGW*) MACHINE=Windows;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

if [ "$MACHINE" == "Windows" ]; then
    echo_info "This script is primarily for Linux/macOS. For native Windows, manual setup is recommended."
    echo_info "You can try to proceed, but it may not work as expected. Using WSL is a good alternative."
fi

# --- Dependency Check & Auto-Install ---
echo_info "Checking for Python 3..."
if ! command_exists python3; then
    echo_error "python3 is not installed. Please install it manually."
fi

# The pre-check for venv is removed as it can be unreliable on some distros.
# We will now attempt to create the venv directly and handle the failure if it occurs.

# --- Setup application directory and virtual environment ---
echo_info "Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
echo_info "Creating Python virtual environment..."
set +e
VENV_CREATE_OUTPUT=$(python3 -m venv "$VENV_DIR" 2>&1)
VENV_EXIT_CODE=$?
set -e

if [ $VENV_EXIT_CODE -ne 0 ]; then
    # Venv creation failed. Let's try to diagnose and fix it automatically.
    echo_info "Initial virtual environment creation failed. Diagnosing..."

    # Check for the common Debian/Ubuntu 'ensurepip' issue, which indicates python3-venv is missing.
    if [[ "$MACHINE" == "Linux" && -f /etc/os-release ]] && (grep -q -E 'ID=(ubuntu|debian)' /etc/os-release) && (echo "$VENV_CREATE_OUTPUT" | grep -q "ensurepip"); then
        echo_info "Detected missing 'python3-venv' package. Attempting to install automatically..."
        
        if command_exists apt; then
            sudo apt-get update && sudo apt-get install -y python3-venv
            echo_info "'python3-venv' installed. Retrying virtual environment creation..."
            
            # Retry creating the venv
            python3 -m venv "$VENV_DIR"
            if [ $? -ne 0 ]; then
                echo_error "Failed to create virtual environment even after installing 'python3-venv'. Please check your Python installation and permissions."
            fi
        else
            echo_error "Automatic installation failed. Please install the equivalent of 'python3-venv' for your distribution and run this script again."
        fi
    else
        # For other errors or other systems, show the generic error.
        echo_error "Failed to create a virtual environment. Please check your Python 3 installation."
        echo "--- Start of Error Log ---"
        echo "$VENV_CREATE_OUTPUT"
        echo "--- End of Error Log ---"
        exit 1
    fi
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

# Check if the chosen directory is in the user's PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
     echo -e "\033[33m[WARNING]\033[0m Your PATH does not seem to include $BIN_DIR."
     
     # Determine shell configuration file
     SHELL_NAME=$(basename "$SHELL")
     if [ "$SHELL_NAME" = "bash" ]; then
         SHELL_CONFIG_FILE="$HOME/.bashrc"
     elif [ "$SHELL_NAME" = "zsh" ]; then
         SHELL_CONFIG_FILE="$HOME/.zshrc"
     else
         # Fallback for other POSIX-compliant shells
         SHELL_CONFIG_FILE="$HOME/.profile"
     fi

     echo_info "Attempting to update your shell configuration file: $SHELL_CONFIG_FILE"

     # The line to add to the config file
     PATH_EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'

     # Add the line if it's not already there
     if ! grep -qF -- "$PATH_EXPORT_LINE" "$SHELL_CONFIG_FILE" 2>/dev/null; then
         echo_info "Adding PATH export to $SHELL_CONFIG_FILE..."
         echo -e "\n# Add enchat to PATH" >> "$SHELL_CONFIG_FILE"
         echo "$PATH_EXPORT_LINE" >> "$SHELL_CONFIG_FILE"
         echo_success "Successfully updated $SHELL_CONFIG_FILE."
         echo -e "\033[1;31m[IMPORTANT]\033[0m You MUST restart your terminal for the 'enchat' command to be available."
     else
         echo_info "PATH configuration already exists in $SHELL_CONFIG_FILE. No changes needed."
         echo -e "\033[33m[WARNING]\033[0m If 'enchat' command is not found, please restart your terminal."
     fi
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