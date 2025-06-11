# 🪟 Enchat Windows Installation Guide

This guide provides detailed instructions for installing Enchat on Windows systems.

## 🚀 Quick Installation

### Option 1: Automatic Installer (Recommended)

Open **PowerShell as Administrator** and run:

```powershell
# Download and run the installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sudodevdante/enchat/main/install-enchat.ps1" -OutFile "install-enchat.ps1"
powershell -ExecutionPolicy Bypass -File install-enchat.ps1
```

### Option 2: Manual Download

1. Download the installer: [install-enchat.ps1](https://raw.githubusercontent.com/sudodevdante/enchat/main/install-enchat.ps1)
2. Right-click on the downloaded file and select "Run with PowerShell"
3. If prompted about execution policy, choose "Yes" or "Run anyway"

## 📋 Prerequisites

The installer will automatically handle these, but for reference:

- **Windows 10 or later** (Windows 11 recommended for best experience)
- **PowerShell 5.1+** (included with Windows 10+)
- **Python 3.6+** (installer will download if missing)
- **Git for Windows** (installer will prompt to install if missing)

## 🔧 Installation Process

The installer performs these steps:

1. **Checks for Python 3.6+** - Downloads and installs via winget if missing
2. **Clones enchat repository** - Downloads latest version from GitHub
3. **Creates virtual environment** - Isolates dependencies (optional)
4. **Installs dependencies** - Installs required Python packages
5. **Creates system launcher** - Adds `enchat` command to your PATH
6. **Tests installation** - Verifies everything works correctly

## 🎯 Installation Options

### Command Line Parameters

```powershell
# Install without virtual environment (global Python packages)
.\install-enchat.ps1 -NoVenv

# Force reinstallation (overwrite existing installation)
.\install-enchat.ps1 -Force

# Combine options
.\install-enchat.ps1 -NoVenv -Force
```

### Installation Locations

- **Enchat files**: `%USERPROFILE%\enchat\` (e.g., `C:\Users\YourName\enchat\`)
- **Launcher scripts**: `%USERPROFILE%\bin\` (added to PATH)
- **Configuration**: `%USERPROFILE%\.enchat.conf`

## ✅ Verification

After installation, test with:

```cmd
# Start a new Command Prompt or PowerShell window
enchat --help
```

You should see the Enchat help message.

## 🚨 Troubleshooting

### Common Issues

#### "enchat is not recognized as a command"

**Solution**: Restart your terminal or run the full path:
```cmd
%USERPROFILE%\bin\enchat.bat
```

#### "Execution of scripts is disabled on this system"

**Solution**: Run PowerShell as Administrator and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Python installation fails

**Solution**: 
1. Install Python manually from [python.org](https://www.python.org/downloads/)
2. During installation, check "Add Python to PATH"
3. Restart terminal and re-run installer

#### Git not found

**Solution**: Install Git for Windows from [git-scm.com](https://git-scm.com/download/win)

### Windows Terminal Setup

For the best experience, use **Windows Terminal** (available from Microsoft Store):

1. Install Windows Terminal from Microsoft Store
2. Set PowerShell as default profile
3. Enable GPU acceleration for better performance

### Antivirus Software

Some antivirus software may flag the installer. This is a false positive. You can:

1. **Temporarily disable real-time protection** during installation
2. **Add an exclusion** for the enchat directory
3. **Run the installer from a trusted location**

## 🔐 Security Features

The Windows installer includes all security features from Linux/macOS:

### Secure Wipe Functionality

```cmd
enchat wipe
```

This command:
- Clears terminal scrollback buffer
- Securely deletes configuration file
- Removes enchat entries from PowerShell history
- Clears current session history

### Desktop Notifications

Windows 10+ users get native toast notifications for new messages when enchat is minimized.

### Isolated Installation

Virtual environment keeps enchat dependencies separate from your system Python packages.

## 🔄 Updates

To update enchat:

```powershell
# Re-run the installer with -Force
.\install-enchat.ps1 -Force
```

Or manually:

```cmd
cd %USERPROFILE%\enchat
git pull origin main
```

## 🗑️ Uninstallation

To completely remove enchat:

1. **Run secure wipe**: `enchat wipe`
2. **Remove installation directory**: 
   ```cmd
   rmdir /s "%USERPROFILE%\enchat"
   rmdir /s "%USERPROFILE%\bin"
   ```
3. **Remove from PATH** (optional): 
   - Open System Properties → Environment Variables
   - Remove `%USERPROFILE%\bin` from user PATH

## 💡 Tips

- **Use Windows Terminal** for the best chat experience
- **Pin PowerShell** to taskbar for quick access
- **Create desktop shortcut** to `%USERPROFILE%\bin\enchat.bat`
- **Run as regular user** (Administrator privileges not required for normal use)

## 🎨 Customization

### PowerShell Profile

Add to your PowerShell profile (`$PROFILE`) for convenience:

```powershell
# Quick enchat alias
function ec { enchat @args }

# Enchat wipe alias
function ecw { enchat wipe }
```

### Windows Terminal Themes

Enchat supports Windows Terminal's color schemes. Popular themes:
- **Campbell Powershell** (default)
- **One Half Dark**
- **Solarized Dark**

## 📞 Support

If you encounter Windows-specific issues:

1. Check this troubleshooting guide
2. Ensure you're using PowerShell (not Command Prompt)
3. Try running PowerShell as Administrator
4. Check Windows version compatibility (Windows 10+ required)

---

**🔐 Ready to chat securely on Windows!** The installation should work identically to Linux/macOS with full feature parity. 