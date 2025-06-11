# Enchat Windows Installer Script
# PowerShell script to install Enchat with the same functionality as Linux/macOS

param(
    [switch]$NoVenv,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting Enchat Windows Installation..." -ForegroundColor Cyan

# 1) Determine installation directory
$ScriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
if (Test-Path "$ScriptDir\enchat.py") {
    $EnchatDir = $ScriptDir
    Write-Host "📁 Using existing Enchat directory: $EnchatDir" -ForegroundColor Green
} else {
    $EnchatDir = "$env:USERPROFILE\enchat"
    Write-Host "📥 Cloning Enchat into $EnchatDir" -ForegroundColor Yellow
    
    # Check if git is available
    try {
        git --version | Out-Null
    } catch {
        Write-Host "❌ Git is required but not found. Please install Git for Windows first." -ForegroundColor Red
        Write-Host "   Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
        exit 1
    }
    
    if (Test-Path $EnchatDir) {
        if ($Force) {
            Remove-Item -Recurse -Force $EnchatDir
        } else {
            Write-Host "Directory $EnchatDir already exists. Use -Force to overwrite." -ForegroundColor Red
            exit 1
        }
    }
    
    git clone https://github.com/sudodevdante/enchat.git $EnchatDir
}

Set-Location $EnchatDir

# 2) Ensure Python3 is available
Write-Host "🔍 Checking Python installation..." -ForegroundColor Yellow

$PythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1
        if ($version -match "Python 3\.") {
            $PythonCmd = $cmd
            Write-Host "✅ Found Python: $version" -ForegroundColor Green
            break
        }
    } catch {
        # Command not found, continue
    }
}

if (-not $PythonCmd) {
    Write-Host "❌ Python 3 not found. Installing Python..." -ForegroundColor Red
    
    # Check if winget is available (Windows Package Manager)
    try {
        winget --version | Out-Null
        Write-Host "📦 Installing Python via winget..." -ForegroundColor Yellow
        winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements
        
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        
        # Try to find Python again
        foreach ($cmd in @("python", "python3", "py")) {
            try {
                $version = & $cmd --version 2>&1
                if ($version -match "Python 3\.") {
                    $PythonCmd = $cmd
                    break
                }
            } catch {
                # Command not found, continue
            }
        }
    } catch {
        Write-Host "❌ Could not install Python automatically." -ForegroundColor Red
        Write-Host "   Please install Python 3.6+ manually from: https://www.python.org/downloads/" -ForegroundColor Yellow
        Write-Host "   Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
        exit 1
    }
    
    if (-not $PythonCmd) {
        Write-Host "❌ Python installation failed or not found in PATH." -ForegroundColor Red
        Write-Host "   Please install Python 3.6+ manually and ensure it's in your PATH." -ForegroundColor Yellow
        exit 1
    }
}

# 3) Setup virtual environment or install packages globally
$VenvDir = "$EnchatDir\venv"
$UseVenv = $false

if (-not $NoVenv) {
    try {
        Write-Host "🐍 Testing virtual environment support..." -ForegroundColor Yellow
        & $PythonCmd -m venv --help | Out-Null
        
        # Test creating a temporary venv
        $TmpVenv = "$EnchatDir\.tmpvenv"
        & $PythonCmd -m venv $TmpVenv
        if (Test-Path "$TmpVenv\Scripts\activate.ps1") {
            Remove-Item -Recurse -Force $TmpVenv
            $UseVenv = $true
            Write-Host "✅ Virtual environment support confirmed" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️  Virtual environment not available - will install globally" -ForegroundColor Yellow
    }
}

if ($UseVenv) {
    Write-Host "🐍 Setting up virtual environment..." -ForegroundColor Yellow
    & $PythonCmd -m venv $VenvDir
    
    $VenvPython = "$VenvDir\Scripts\python.exe"
    $VenvPip = "$VenvDir\Scripts\pip.exe"
    
    if (-not (Test-Path $VenvPython)) {
        Write-Host "❌ Virtual environment creation failed" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "📦 Installing dependencies in virtual environment..." -ForegroundColor Yellow
    & $VenvPip install --upgrade pip
    & $VenvPip install requests colorama cryptography
} else {
    Write-Host "📦 Installing dependencies globally..." -ForegroundColor Yellow
    & $PythonCmd -m pip install --user --upgrade pip
    & $PythonCmd -m pip install --user requests colorama cryptography
}

# 4) Create enhanced launcher with wipe functionality
$LauncherDir = "$env:USERPROFILE\bin"
$LauncherBat = "$LauncherDir\enchat.bat"
$LauncherPs1 = "$LauncherDir\enchat.ps1"

if (-not (Test-Path $LauncherDir)) {
    New-Item -ItemType Directory -Path $LauncherDir | Out-Null
}

# Create PowerShell launcher script
$LauncherContent = @"
# Enchat Launcher Script for Windows
param(
    [string]`$Action = `$args[0]
)

function Invoke-EnchatWipe {
    Write-Host "== ENCHAT ZERO-TRACE CLEANER ==" -ForegroundColor Red
    
    # 1. Clear terminal screen and scrollback
    Clear-Host
    
    # 2. Securely remove .enchat.conf if present
    `$ConfFile = "`$env:USERPROFILE\.enchat.conf"
    if (Test-Path `$ConfFile) {
        Remove-Item -Force `$ConfFile
        Write-Host "Enchat config wiped." -ForegroundColor Yellow
    }
    
    # 3. Remove Enchat entries from PowerShell history
    try {
        `$HistoryPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path `$HistoryPath) {
            `$history = Get-Content `$HistoryPath
            `$filteredHistory = `$history | Where-Object { `$_ -notmatch 'enchat' }
            `$filteredHistory | Set-Content `$HistoryPath
        }
    } catch {
        # Ignore errors if PSReadline is not available
    }
    
    # 4. Clear current session history
    Clear-History
    
    Write-Host "All Enchat traces wiped. Ready for next use." -ForegroundColor Green
}

if (`$Action -eq "wipe") {
    Invoke-EnchatWipe
} else {
    Set-Location "$EnchatDir"
"@

if ($UseVenv) {
    $LauncherContent += @"
    & "$VenvPython" enchat.py @args
"@
} else {
    $LauncherContent += @"
    & $PythonCmd enchat.py @args
"@
}

$LauncherContent += @"
}
"@

$LauncherContent | Out-File -FilePath $LauncherPs1 -Encoding UTF8

# Create batch file wrapper for easier command line usage
$BatchContent = @"
@echo off
powershell -ExecutionPolicy Bypass -File "$LauncherPs1" %*
"@

$BatchContent | Out-File -FilePath $LauncherBat -Encoding ASCII

# 5) Add ~/bin to PATH if needed
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$BinPath = $LauncherDir

if ($UserPath -notlike "*$BinPath*") {
    Write-Host "🔄 Adding $BinPath to user PATH..." -ForegroundColor Yellow
    
    if ($UserPath) {
        $NewPath = $UserPath + ";" + $BinPath
    } else {
        $NewPath = $BinPath
    }
    
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    
    # Update current session PATH
    $env:PATH = $env:PATH + ";" + $BinPath
    
    Write-Host "✅ Added to PATH. You may need to restart your terminal for the change to take effect." -ForegroundColor Green
}

# 6) Test the installation
Write-Host ""
Write-Host "🧪 Testing installation..." -ForegroundColor Yellow

try {
    if ($UseVenv) {
        $TestResult = & $VenvPython -c "import requests, colorama, cryptography; print('Dependencies OK')"
    } else {
        $TestResult = & $PythonCmd -c "import requests, colorama, cryptography; print('Dependencies OK')"
    }
    
    if ($TestResult -match "Dependencies OK") {
        Write-Host "✅ Dependencies test passed" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Dependencies test inconclusive" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Dependencies test failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 7) Success message
Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Commands available:" -ForegroundColor White
Write-Host "  enchat              Start encrypted chat" -ForegroundColor Cyan
Write-Host "  enchat wipe         Securely remove all traces" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: If 'enchat' command is not recognized, restart your terminal" -ForegroundColor Yellow
Write-Host "      or run: $LauncherBat" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔐 Enchat is now ready for secure, encrypted terminal chat!" -ForegroundColor Green 