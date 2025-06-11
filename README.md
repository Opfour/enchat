<div align="center">
  <img src="https://sudosallie.com/enchatlogo.png" alt="Enchat Logo" width="400">
</div>

# 🔐 Enchat - Encrypted Terminal Chat

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

**Enchat** brings **military-grade encryption** directly to your terminal, enabling completely private conversations without corporate surveillance or data harvesting. Chat securely with colleagues, friends, or team members knowing that your messages are **cryptographically protected** and invisible to servers, governments, and eavesdroppers.

**Why Enchat?** Because your conversations deserve better than Big Tech's "encrypted" platforms that still profile you, track you, and own your data. Take back control with a tool that's **truly private by design** - no accounts, no tracking, no compromises.

## 🔒 Security & Encryption

### **How Your Messages Stay Safe**
- **End-to-end encryption** using Fernet (AES 128 in CBC mode + HMAC-SHA256)
- **Client-side encryption** - messages are encrypted before leaving your device
- **Server blindness** - ntfy servers only see encrypted blobs, never plaintext
- **Authenticated encryption** - prevents message tampering and ensures integrity
- **Strong key derivation** - PBKDF2-HMAC-SHA256 with 100,000 iterations and static salt ensures a robust encryption key from your passphrase

### **Message Flow Security**
```
Your Message → [Encrypt] → Encrypted Blob → ntfy Server → Encrypted Blob → [Decrypt] → Recipient
```

The ntfy server acts as a **message relay only** - it cannot decrypt your messages without your passphrase. Even if the server is compromised, your conversations remain secure.

### **Privacy Guarantees**
- 🔐 **Zero knowledge** - servers never see message content
- 🎭 **Anonymous** - no accounts or personal information required
- 🧹 **Clean exit** - secure wipe removes all traces

## ✨ Features

- **Real-time encrypted chat** with timestamps and status indicators
- **Multiple server options** including dedicated enchat server
- **Self-hosted ntfy support** for complete infrastructure control
- **Auto-reconnection** with smart retry logic
- **Desktop notifications** (Linux, macOS)
- **Command system** (`/help`, `/clear`, `/exit`, `/server`, `/who`)
- **Smart input handling** and message validation
- **Cross-platform** terminal support

## 🚀 Quick Start

### Installation

#### Automatic Installer (Recommended)

**Windows:**
```powershell
# Download and run installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sudosallie/enchat/main/install-enchat.ps1" -OutFile "install-enchat.ps1"
powershell -ExecutionPolicy Bypass -File install-enchat.ps1
```

**Linux/macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/sudosallie/enchat/main/install-enchat.sh | bash
```

Both installers provide:
- ✅ **Automatic dependency management** (Python, pip packages)
- ✅ **System launcher** (`enchat` command globally available)
- ✅ **Secure wipe functionality** (`enchat wipe` removes all traces)
- ✅ **Cross-platform compatibility** (identical features on all systems)
- ✅ **Desktop notifications** (Windows 10+ toast, Linux notify-send, macOS osascript)

#### Manual Setup
```bash
git clone https://github.com/sudosallie/enchat.git
cd enchat
pip install requests colorama cryptography
chmod +x enchat.py  # Linux/macOS only
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
  1) Default ntfy server (https://ntfy.sh)
     - Public server with rate limits
  2) Enchat ntfy server (https://enchat.sudosallie.com)
     - Dedicated server for enchat with more generous limits
  3) Custom server
     - Your own or another ntfy server
Enter choice [1-3] (default: 1): 2

💾 Save settings for auto-reconnect? [Y/n]: y
```

### Chat Interface

```
┌─────────────────────────────────────────────────────────────────────────────┐
│🟢 my-secret-room | alice | ntfy.sh                                           │
└─────────────────────────────────────────────────────────────────────────────┘

[14:32:15] ℹ Joined room 'my-secret-room' • Type /exit to quit, /clear to clear screen
[14:32:16] ℹ Connected successfully! Ready to chat!

[14:32:20] → bob joined the chat
[14:32:25] bob: Hey Alice! 👋
[14:32:30] alice: Hi Bob! How are you?
[14:32:35] bob: This is completely private!

💬 > 
```

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

1. **Default Server** (ntfy.sh)
   - Public server with rate limits
   - Good for occasional use

2. **Dedicated Enchat Server** (enchat.sudosallie.com)
   - Optimized for chat with generous rate limits
   - Recommended for regular use

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
| `/server` | Display current server information |
| `/ratelimit` | Show rate limiting information and tips |

### Self-Hosted ntfy

Enchat works with the public ntfy.sh server by default, but that service may enforce rate limits. Hosting your own ntfy server on a VPS gives you unlimited usage and full infrastructure control. It's optional but recommended for high‑volume or sensitive communications.

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
- **Platforms:** Linux, macOS, Windows (full feature parity across all platforms)

## 🐛 Troubleshooting

**Connection Issues:**
- Verify internet connection and ntfy server accessibility
- Try default ntfy.sh if custom server fails

**Rate Limiting Issues:**
- If you see HTTP 429 errors, the server is rate limiting your requests
- Use the `/ratelimit` command to see tips on avoiding rate limits
- Consider switching to the enchat server with `--enchat-server`
- For high-volume use, set up your own ntfy server

**Encryption Issues:**
- Ensure exact passphrase match across all participants
- Check for typos in room names (case-sensitive)

**Display Issues:**
- Ensure terminal supports Unicode characters
- Update terminal emulator for proper color support
- **Windows:** Use Windows Terminal or PowerShell for best experience

**Windows-Specific:**
- Run installer with: `powershell -ExecutionPolicy Bypass -File install-enchat.ps1`
- Toast notifications require Windows 10 or later
- Use Windows Terminal for optimal Unicode/color support
- PowerShell history cleaning happens automatically with `enchat wipe`

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [ntfy.sh](https://ntfy.sh) for secure notification infrastructure
- [cryptography](https://cryptography.io/) for robust encryption implementation

---

**Secure terminal communication made simple**
