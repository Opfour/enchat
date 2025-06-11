# Enchat Windows Installer
# Equivalent to install-enchat.sh for Windows PowerShell

param(
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Enchat Windows Installer

This script will:
- Check for Python 3.6+ installation
- Install Python if needed (via Windows Store or python.org)
- Clone Enchat repository if not present
- Set up virtual environment with dependencies
- Create global 'enchat' command with wipe functionality
- Add enchat to PATH for easy access

Usage:
  powershell -ExecutionPolicy Bypass -File install-enchat.ps1

"@ -ForegroundColor Cyan
    exit 0
}

# Enable error handling
$ErrorActionPreference = "Stop"

Write-Host "🔐 Enchat Windows Installer" -ForegroundColor Magenta
Write-Host "==============================" -ForegroundColor Magenta

# 1) Determine installation directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnchatPy = Join-Path $ScriptDir "enchat.py"

if (Test-Path $EnchatPy) {
    $EnchatDir = $ScriptDir
    Write-Host "📁 Using existing Enchat directory: $EnchatDir" -ForegroundColor Green
} else {
    $EnchatDir = Join-Path $env:USERPROFILE "enchat"
    Write-Host "📥 Cloning Enchat into $EnchatDir" -ForegroundColor Blue
    
    # Check if git is available
    try {
        git --version | Out-Null
    } catch {
        Write-Host "❌ Git is not installed. Please install Git first:" -ForegroundColor Red
        Write-Host "   https://git-scm.com/download/win" -ForegroundColor Yellow
        exit 1
    }
    
    if (Test-Path $EnchatDir) {
        Remove-Item -Recurse -Force $EnchatDir
    }
    git clone https://github.com/sudodevdante/enchat.git $EnchatDir
}

Set-Location $EnchatDir

# 2) Check for Python installation
$PythonCmd = $null
$PythonVersion = $null

# Try different Python commands
$PythonCommands = @("python", "python3", "py")
foreach ($cmd in $PythonCommands) {
    try {
        $version = & $cmd --version 2>&1
        if ($version -match "Python (\d+)\.(\d+)") {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            if ($major -eq 3 -and $minor -ge 6) {
                $PythonCmd = $cmd
                $PythonVersion = $version
                break
            }
        }
    } catch {
        # Command not found, continue
    }
}

if (-not $PythonCmd) {
    Write-Host "🔧 Python 3.6+ not found. Installing Python..." -ForegroundColor Yellow
    
    # Try to install Python via winget (Windows 10 1809+)
    try {
        winget install Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        Write-Host "✅ Python installed via winget" -ForegroundColor Green
        
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        # Try to find Python again
        Start-Sleep 2
        foreach ($cmd in $PythonCommands) {
            try {
                $version = & $cmd --version 2>&1
                if ($version -match "Python (\d+)\.(\d+)") {
                    $major = [int]$matches[1]
                    $minor = [int]$matches[2]
                    if ($major -eq 3 -and $minor -ge 6) {
                        $PythonCmd = $cmd
                        $PythonVersion = $version
                        break
                    }
                }
            } catch {
                # Command not found, continue
            }
        }
    } catch {
        Write-Host "❌ Could not install Python automatically." -ForegroundColor Red
        Write-Host "Please install Python 3.6+ manually from:" -ForegroundColor Yellow
        Write-Host "   https://www.python.org/downloads/" -ForegroundColor Cyan
        Write-Host "   or from Microsoft Store" -ForegroundColor Cyan
        exit 1
    }
}

if (-not $PythonCmd) {
    Write-Host "❌ Python 3.6+ is still not available after installation attempt." -ForegroundColor Red
    Write-Host "Please restart your terminal and try again, or install Python manually." -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Found Python: $PythonVersion" -ForegroundColor Green

# 3) Check for pip
try {
    & $PythonCmd -m pip --version | Out-Null
    Write-Host "✅ pip is available" -ForegroundColor Green
} catch {
    Write-Host "🔧 Installing pip..." -ForegroundColor Yellow
    & $PythonCmd -m ensurepip --upgrade
}

# 4) Set up virtual environment
$VenvDir = Join-Path $EnchatDir "venv"
$UseVenv = $false

try {
    & $PythonCmd -m venv --help | Out-Null
    $UseVenv = $true
    Write-Host "✅ Virtual environment support available" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Virtual environment not available - will install to user site" -ForegroundColor Yellow
}

if ($UseVenv) {
    Write-Host "🐍 Setting up virtual environment..." -ForegroundColor Blue
    
    if (Test-Path $VenvDir) {
        Remove-Item -Recurse -Force $VenvDir
    }
    
    & $PythonCmd -m venv $VenvDir
    
    # Activate virtual environment
    $ActivateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
    & $ActivateScript
    
    Write-Host "📦 Installing dependencies in virtual environment..." -ForegroundColor Blue
    & python -m pip install --upgrade pip
    & python -m pip install requests colorama cryptography
} else {
    Write-Host "📦 Installing dependencies to user site..." -ForegroundColor Blue
    & $PythonCmd -m pip install --user --upgrade pip
    & $PythonCmd -m pip install --user requests colorama cryptography
}

# 5) Create launcher script in user's local bin directory
$LocalBin = Join-Path $env:USERPROFILE "bin"
if (-not (Test-Path $LocalBin)) {
    New-Item -ItemType Directory -Path $LocalBin | Out-Null
}

$LauncherPath = Join-Path $LocalBin "enchat.bat"
$LauncherPs1Path = Join-Path $LocalBin "enchat.ps1"

# Create batch launcher for easy CMD access
$BatchContent = @"
@echo off
setlocal

if "%1"=="wipe" (
    powershell -ExecutionPolicy Bypass -File "$LauncherPs1Path" wipe
    goto :eof
)

if "%1"=="help" (
    powershell -ExecutionPolicy Bypass -File "$LauncherPs1Path" help
    goto :eof
)

cd /d "$EnchatDir"
"@

if ($UseVenv) {
    $BatchContent += @"

call "$VenvDir\Scripts\activate.bat"
python enchat.py %*
"@
} else {
    $BatchContent += @"

$PythonCmd enchat.py %*
"@
}

$BatchContent | Out-File -FilePath $LauncherPath -Encoding ASCII

# Create PowerShell launcher with wipe functionality
$PowerShellContent = @"
param(
    [Parameter(ValueFromRemainingArguments=`$true)]
    `$Arguments
)

function Invoke-EnchatWipe {
    Write-Host "== ENCHAT ZERO-TRACE CLEANER ==" -ForegroundColor Red
    
    # 1. Clear terminal
    Clear-Host
    
    # 2. Remove .enchat.conf if present
    `$ConfPath = Join-Path `$env:USERPROFILE ".enchat.conf"
    if (Test-Path `$ConfPath) {
        Remove-Item -Force `$ConfPath
        Write-Host "Enchat config wiped." -ForegroundColor Green
    }
    
    # 3. Clear PowerShell history of enchat commands
    `$HistoryPath = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path `$HistoryPath) {
        `$content = Get-Content `$HistoryPath | Where-Object { `$_ -notmatch "enchat" }
        `$content | Set-Content `$HistoryPath
    }
    
    # 4. Clear current session history
    Clear-History
    
    Write-Host "All Enchat traces wiped. Ready for next use." -ForegroundColor Green
}

function Show-EnchatHelp {
    Write-Host @"
Enchat - Encrypted Terminal Chat

Usage:
  enchat                 Start encrypted chat
  enchat wipe           Remove all traces of enchat usage
  enchat help           Show this help message
  enchat [options]      Pass options to enchat.py

Examples:
  enchat --server https://custom-server.com
  enchat --reset
  enchat --help

"@ -ForegroundColor Cyan
}

if (`$Arguments.Count -gt 0 -and `$Arguments[0] -eq "wipe") {
    Invoke-EnchatWipe
    return
}

if (`$Arguments.Count -gt 0 -and `$Arguments[0] -eq "help") {
    Show-EnchatHelp
    return
}

# Change to enchat directory
Set-Location "$EnchatDir"
"@

if ($UseVenv) {
    $PowerShellContent += @"

# Activate virtual environment
& "$VenvDir\Scripts\Activate.ps1"
& python enchat.py @Arguments
"@
} else {
    $PowerShellContent += @"

# Run enchat with system Python
& $PythonCmd enchat.py @Arguments
"@
}

$PowerShellContent | Out-File -FilePath $LauncherPs1Path -Encoding UTF8

# 6) Add to PATH if needed
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notmatch [regex]::Escape($LocalBin)) {
    Write-Host "🔄 Adding $LocalBin to user PATH..." -ForegroundColor Blue
    $NewPath = $UserPath + ";" + $LocalBin
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    $env:PATH += ";" + $LocalBin
    Write-Host "✅ Added to PATH. Restart terminal or refresh environment for global access." -ForegroundColor Green
} else {
    Write-Host "✅ $LocalBin already in PATH" -ForegroundColor Green
}

# 7) Test the installation
Write-Host ""
Write-Host "🧪 Testing installation..." -ForegroundColor Blue
try {
    Set-Location $EnchatDir
    if ($UseVenv) {
        & "$VenvDir\Scripts\python.exe" -c "import requests, colorama, cryptography; print('✅ All dependencies available')"
    } else {
        & $PythonCmd -c "import requests, colorama, cryptography; print('✅ All dependencies available')"
    }
} catch {
    Write-Host "⚠️  Dependency test failed. You may need to install manually:" -ForegroundColor Yellow
    Write-Host "   pip install requests colorama cryptography" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host "▶️  Start chat: " -NoNewline -ForegroundColor White
Write-Host "enchat" -ForegroundColor Cyan
Write-Host "▶️  Wipe traces: " -NoNewline -ForegroundColor White  
Write-Host "enchat wipe" -ForegroundColor Cyan
Write-Host "▶️  Show help: " -NoNewline -ForegroundColor White
Write-Host "enchat help" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: If 'enchat' command is not found, restart your terminal or run:" -ForegroundColor Yellow
Write-Host "  `$env:PATH += ';$LocalBin'" -ForegroundColor Cyan 