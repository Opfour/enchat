<div align="center">
  <img src="https://sudosallie.com/enchatlogo.png" alt="Enchat Logo" width="400">
</div>

# 🔐 Enchat - Encrypted Under The Radar Chat
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

**Enchat** brings **end-to-end encrypted communication** directly to your terminal, enabling completely private conversations without corporate surveillance or data harvesting. Chat securely with colleagues, friends, or team members knowing that your messages are **cryptographically protected** and invisible to servers, governments, and eavesdroppers.

**Why Enchat?** Because your conversations deserve better than Big Tech's "encrypted" platforms that still profile you, track you, and own your data. Take back control with a tool that's **truly private by design** - no accounts, no tracking, no compromises.

## 🔒 Security & Encryption

### **How Your Messages Stay Safe**
- **End-to-end encryption** using AES-256 in CBC mode with HMAC-SHA256 and PBKDF2-based key derivation for enhanced security
- **Automatic session-based encryption** - Each chat session silently generates and uses a unique temporary key
- **Perfect Forward Secrecy** - When a session ends, its messages become permanently unreadable - even with the passphrase
- **Double-layer encryption** - Messages are automatically encrypted with both session keys and room-specific keys
- **Client-side encryption** - All encryption happens on your device before transmission
- **Server blindness** - ntfy servers only see encrypted blobs, never plaintext
- **Authenticated encryption** - prevents message tampering and ensures integrity
- **Strong key derivation** - PBKDF2-HMAC-SHA256 with 100,000 iterations and static salt
- **Seamless key rotation** - New session keys are automatically generated whenever a room becomes empty
- **Invisible key exchange** - New participants automatically receive encrypted session keys without user interaction
- **Isolated sessions** - Different passphrases create completely separate chat environments
- **No stored keys** - Session keys are never saved to disk in plain text
- **Metadata protection** - usernames, timestamps, and system events are also encrypted
- **Privacy by design** - no personal information stored or transmitted in plaintext

### **Why Messages Cannot Be Intercepted**
Even if an attacker:
- Has the room passphrase
- Captures all network traffic
- Compromises the server
- Gains access to stored files

They still cannot read messages because:
1. Each message is encrypted with a temporary session key
2. Session keys only exist during active chat sessions
3. Session keys are never stored in plain text
4. When a session ends, its messages become permanently unreadable

### **Message Flow Security**
```
Your Message → [Session Key Encrypt] → [Room Key Encrypt] → Encrypted Blob → ntfy Server → Encrypted Blob → [Room Key Decrypt] → [Session Key Decrypt] → Recipient
```

The ntfy server acts as a **blind message relay** - it cannot decrypt your messages without both:
- The room passphrase
- AND the temporary session key (which is automatically managed)
Even if the server is compromised, your conversations remain secure.

### **User Experience**
All you need to remember is your room passphrase - Enchat handles all the complex security automatically:
- Session keys are generated and exchanged invisibly
- Key rotation happens seamlessly when rooms empty
- New participants get access automatically when they join
- No additional passwords or keys to manage

### **Privacy Guarantees**
- 🔐 **Zero knowledge** - servers never see message content, usernames, timestamps, or file data
- 🎭 **Anonymous** - no accounts or personal information required
- 🛡️ **Metadata protection** - join/leave events, system messages, and filenames encrypted
- 🧹 **Clean exit** - secure wipe removes all traces including downloaded files
- 📱 **Secure notifications** - desktop alerts never show message or file content
- 📁 **File privacy** - file transfers use same AES-256 encryption as messages

## ✨ Features

- **Real-time encrypted chat** with timestamps and status indicators
- **🔒 Encrypted file sharing** with chunked transfer up to 5MB per file
- **🧅 Tor support** for enhanced anonymity
- **Multiple server options** including dedicated enchat server
- **Self-hosted ntfy support** for complete infrastructure control
- **Auto-reconnection** with smart retry logic
- **Desktop notifications** (Linux, macOS)
- **Command system** (`/help`, `/clear`, `/exit`, `/server`, `/who`, `/share`, `/files`, `/download`, `/lottery`)
- **Smart input handling** and message validation
- **Cross-platform** terminal support

## 🚀 Quick Start

### Installation

#### Linux/macOS Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/sudodevdante/enchat.git
cd enchat

# Run the installer (inspect install-enchat.sh first if you want)
./install-enchat.sh
```

The installer provides:
- ✅ **Automatic dependency management** (Python, pip packages)
- ✅ **Global `enchat` command** (works from anywhere)
- ✅ **Secure wipe functionality** (`enchat wipe` removes all traces)
- ✅ **Desktop notifications** (Linux notify-send, macOS osascript)

#### Manual Installation (All Platforms)

```bash
# Clone or download
git clone https://github.com/sudodevdante/enchat.git
cd enchat

# Install dependencies (keyring is optional but recommended)
pip install requests colorama cryptography keyring

# Make executable (Linux/macOS only)
chmod +x enchat.py

# Run enchat
python enchat.py
```

#### Windows Users

If you don't have `git`, download the repository as a ZIP file from GitHub, extract it, then:

```powershell
cd enchat
pip install requests colorama cryptography keyring
python enchat.py
```

### First Run

```bash
enchat
```

Setup interface:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ENCRYPTED TERMINAL CHAT                           │
└─────────────────────────────────────────────────────────────────────────────┘

Welcome to Enchat! Let's set up your encrypted chat.

🏠 Room name (unique, secret): my-secret-room
👤 Your nickname: alice
🔐 Encryption passphrase (hidden): ••••••••

🌐 Select a ntfy server:
  1) Enchat ntfy server (https://enchat.sudodevdante.com) - Recommended
     - Dedicated server for enchat with generous limits
  2) Default ntfy server (https://ntfy.sh)
     - Public server with rate limits
  3) Custom server
     - Your own or another ntfy server
Enter choice [1-3] (default: 1): 1

💾 Save settings for auto-reconnect? [Y/n]: y
```

### Chat Interface

<div align="center">
  <img src="https://sudosallie.com/enchat.png" alt="Enchat Interface" width="800">
</div>

## 📁 Encrypted File Sharing

Enchat supports **secure, end-to-end encrypted file transfer** using the same AES-256 encryption as your messages. Share documents, images, code, and any file type up to 5MB with complete privacy.

### **🔒 File Transfer Security**
- **End-to-end encryption** - Files are encrypted into 6KB chunks before transmission
- **Zero server knowledge** - ntfy servers only see encrypted blobs, never file content or names
- **Integrity verification** - SHA256 hash verification ensures perfect file reconstruction
- **Directory traversal protection** - Filenames are sanitized to prevent malicious path injection
- **Secure cleanup** - Temporary files are automatically removed after download

### **📋 File Sharing Commands**

| Command | Description | Example |
|---------|-------------|---------|
| `/share <filepath>` | Upload and share a file | `/share ~/document.pdf` |
| `/files` | List available files for download | `/files` |
| `/download <file_id>` | Download a file to `downloads/` folder | `/download a1b2c3d4` |

### **🎲 In-Chat Lottery**

Enchat includes a fun, simple lottery system accessible via the `/lottery` command. Use `/lottery help` inside the chat to see all available options, including:

- **/lottery start**: Kicks off a new lottery.
- **/lottery enter**: Joins the active lottery.
- **/lottery draw**: The user who started the lottery can draw a winner.
- **/lottery status**: Check who has entered.
- **/lottery cancel**: The starter can cancel an active lottery.

### **🚀 File Sharing Workflow**

#### **1. Upload a File**
```bash
💬 > /share ~/presentation.pdf
🔍 Preparing to share: /Users/alice/presentation.pdf
📤 Sharing: presentation.pdf (2.1MB, 347 chunks)
   File ID: a1b2c3d4 (also in your /files for reference)
📤 Upload progress: 10% (35/347)
📤 Upload progress: 50% (174/347)
📤 Upload progress: 100% (347/347)
✅ Upload complete: presentation.pdf
```

#### **2. View Available Files**
```bash
💬 > /files
📂 AVAILABLE FILES (2)
  a1b2c3d4: presentation.pdf (2.1MB) from alice (you) - ✅ Ready
  x7y9z2w5: report.docx (0.5MB) from bob - ✅ Ready
```

#### **3. Download a File**
```bash
💬 > /download a1b2c3d4
✅ Downloaded: presentation.pdf (2.1MB)
📁 Saved to: downloads/presentation.pdf
```

### **📊 File Transfer Specifications**

| **Specification** | **Limit/Details** |
|-------------------|-------------------|
| **Maximum file size** | **5MB per file** |
| **Supported file types** | **All types** (binary safe) |
| **Chunk size** | **6KB** (optimal for ntfy) |
| **Concurrent transfers** | **100+ files** (RAM limited) |
| **Download location** | **`downloads/` folder** |
| **File name conflicts** | **Auto-rename** (`file_1.txt`) |

### **🗂️ Supported File Types**

Enchat's binary-safe encryption supports **all file types**:

- **📄 Documents**: PDF, DOCX, TXT, MD, RTF
- **🖼️ Images**: JPG, PNG, GIF, SVG, BMP, TIFF
- **🎵 Audio**: MP3, WAV, FLAC, M4A, OGG
- **🎬 Video**: MP4, AVI, MKV, MOV, WMV
- **💾 Archives**: ZIP, TAR.GZ, RAR, 7Z
- **💻 Code**: PY, JS, CPP, JAVA, GO, RS
- **📊 Data**: JSON, CSV, XML, SQL, YAML
- **⚙️ Executables**: EXE, APP, DEB, DMG, MSI

### **🔧 File Transfer Security Details**

#### **Encryption Process**
```
Original File → [Split into 6KB chunks] → [AES-256 encrypt each chunk] 
→ [Send via ntfy] → [Receive chunks] → [Decrypt chunks] → [Verify SHA256] 
→ [Reconstruct file] → [Save to downloads/]
```

#### **Security Guarantees**
- ✅ **Server blindness** - ntfy servers cannot decrypt file content
- ✅ **Metadata protection** - filenames encrypted in transit
- ✅ **Integrity verification** - SHA256 hash prevents corruption
- ✅ **Path injection protection** - filenames sanitized against `../../../` attacks
- ✅ **Memory cleanup** - chunks removed from memory after download
- ✅ **Temp file cleanup** - secure removal of temporary files

### **⚡ Performance & Limits**

#### **Transfer Speed**
- **Small files (< 1MB)**: ~10-20 seconds
- **Medium files (1-3MB)**: ~30-60 seconds  
- **Large files (3-5MB)**: ~1-3 minutes

*Speed depends on ntfy server limits and network connection*

#### **Recommended Usage**
- **ntfy.sh**: Up to 5MB, occasional use
- **enchat.sudodevdante.com**: Up to 5MB, regular use
- **Self-hosted ntfy**: Up to 25MB+ (configurable)

### **🛡️ File Sharing Best Practices**

✅ **Security:**
- Only share files with trusted room participants
- Verify file integrity after download (files include SHA256 verification)
- Use strong room passphrases when sharing sensitive files
- Consider self-hosting ntfy for highly sensitive files

✅ **Performance:**
- Keep files under 5MB for optimal transfer speed
- Use file compression (ZIP) for multiple small files
- Avoid sharing files during high network congestion

⚠️ **Important Notes:**
- Files are stored in memory during transfer - avoid sharing too many large files simultaneously
- Downloaded files go to `downloads/` folder and are excluded from git
- File transfers use the same encryption as messages - same security level

## 🛠️ Configuration

### Command Line Options

```bash
enchat --help                                    # Show help
enchat --reset                                   # Clear saved settings
enchat --server https://your-ntfy.example.com   # Use custom ntfy server
enchat --enchat-server                          # Use dedicated enchat server
enchat --default-server                         # Use default ntfy.sh server
enchat wipe                                      # Securely remove all traces
```

### Server Options

Enchat supports multiple ntfy servers:

1. **Dedicated Enchat Server** (enchat.sudodevdante.com) - **Default & Recommended**
   - Optimized for chat with generous rate limits
   - Best performance and reliability for enchat

2. **Default Server** (ntfy.sh)
   - Public server with rate limits
   - Good for occasional use

3. **Self-Hosted Server**
   - Complete control over infrastructure
   - Unlimited usage with no rate limits
   - Best for sensitive or high-volume communications

You can select your server during initial setup or use command line options to specify.

### In-Chat Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/clear` | Clear screen |
| `/exit` | Leave chat |
| `/who` | Show all active room participants |
| `/stats` | Session statistics and encryption info |
| `/security` | Detailed security and privacy overview |
| `/server` | Display current server information |
| `/notifications` | Toggle desktop notifications on/off |
| `/share <filepath>` | Share a file (up to 5MB, all types supported) |
| `/files` | List available files for download |
| `/download <file_id>` | Download a file to downloads/ folder |
| `/lottery` | In-chat lottery system. Use `/lottery help` for details. |
| `/poll` | Create a poll. e.g., `/poll "Title" | "A1" | "A2"` |
| `/vote` | Vote in a poll. e.g., `/vote 1` |

### Public Rooms

Join public, less-secure chat rooms using the `enchat public <room_name>` command. These are good for casual conversation where privacy is not the primary concern.

Available public rooms:
- `lobby` - General chat and meeting place.
- `gaming` - For discussing games and finding players.
- `lottery` - A dedicated room for running lotteries.

### Self-Hosted ntfy

Enchat works with the public ntfy.sh server by default, but that service may enforce rate limits. Hosting your own nfy server on a VPS gives you unlimited usage and full infrastructure control. It's optional but recommended for high‑volume or sensitive communications.

To get started, run the included setup script on your VPS (you'll need a domain pointing to the server):

```bash
# On your VPS
./setup-selfhosted-ntfy-server.sh
```

This script installs and configures ntfy (via Docker or a systemd service), obtains TLS certificates from Let's Encrypt, and sets up a service ready to serve at your domain (e.g., `ntfy.yourdomain.com`).

Once your ntfy server is running, point Enchat to it:

```bash
enchat --server https://your-ntfy-domain.com
```

## 🔧 How It Works

**Architecture:**
```
Alice ←→ [Encrypted Channel] ←→ ntfy Server ←→ [Encrypted Channel] ←→ Bob
```

1. **Message encryption** happens on your device using your shared passphrase
2. **Encrypted data** is sent to ntfy server (never plaintext)
3. **Server relays** the encrypted blob without decryption capability
4. **Recipients decrypt** using the same passphrase

**Security Properties:**
- Server compromise doesn't expose message content
- Network sniffing only reveals encrypted data
- Forward secrecy through unique room sessions
- Message authentication prevents tampering

## 🔒 Security Best Practices

✅ **Recommended:**
- Use strong passphrases (12+ characters)
- Share room details through secure channels
- Use different rooms for different groups
- Self-host for sensitive communications

⚠️ **Important:**
- All participants need the exact same passphrase
- Room names are case-sensitive
- Don't reuse room names across different conversations

### Configuration Security

Settings are stored in `~/.enchat.conf`. Secure this file:
```bash
chmod 600 ~/.enchat.conf
```

For maximum security, don't save your passphrase (choose 'n' during setup).

## 📋 Requirements

- **Python 3.6+**
- **Dependencies:** `requests`, `colorama`, `cryptography`
- **Optional:** `keyring` (for secure passphrase storage in system keychain)
- **Platforms:** Linux, macOS, Windows (full feature parity across all platforms)
- **Storage:** ~10MB free space for `downloads/` folder (auto-created, git-ignored)

## 🐛 Troubleshooting

**Connection Issues:**
- Verify internet connection and ntfy server accessibility
- If using `--tor`, ensure the Tor service is running locally on port 9050.
- Try default ntfy.sh if custom server fails

**Rate Limiting Issues:**
- If you see HTTP 429 errors, the server is rate limiting your requests
- Rate limiting is automatically handled with smart retry logic
- Consider switching to the enchat server with `--enchat-server`
- For high-volume use, set up your own ntfy server

**Encryption Issues:**
- Ensure exact passphrase match across all participants
- Check for typos in room names (case-sensitive)

**Display Issues:**
- Ensure terminal supports Unicode characters
- Update terminal emulator for proper color support
- **Windows:** Use Windows Terminal or PowerShell for best experience

**File Transfer Issues:**
- Large file transfers may take several minutes - be patient
- If upload fails, check file size (max 5MB) and file permissions
- Files are saved to `downloads/` folder in the enchat directory
- For transfer errors, try again or check server connectivity with `/server`

**Windows-Specific:**
- Run installer with: `powershell -ExecutionPolicy Bypass -File install-enchat.ps1`
- Toast notifications require Windows 10 or later
- Use Windows Terminal for optimal Unicode/color support
- PowerShell history cleaning happens automatically with `enchat wipe`
- File paths: Use forward slashes or escape backslashes: `/share C:/file.txt` or `/share C:\\file.txt`

## 📄 License

Copyright © 2025 sudodevdante All rights reserved.

Permission is granted to any user to install and execute this Software
for internal purposes only. Redistribution, modification, decompilation
or any other use is prohibited without prior written consent of the
copyright holder.

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND…

## 🙏 Acknowledgments

- [ntfy.sh](https://ntfy.sh) for secure notification infrastructure
- [cryptography](https://cryptography.io/) for robust encryption implementation

---

**Secure terminal communication made simple**

