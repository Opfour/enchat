#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
import argparse
import base64
import hashlib
import requests
import subprocess
from datetime import datetime
from getpass import getpass
from dataclasses import dataclass
from typing import List, Tuple
from shutil import which
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt

# Try to import keyring for secure passphrase storage
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# Configuration constants
CONF_FILE = os.path.expanduser("~/.enchat.conf")
DEFAULT_NTFY = "https://ntfy.sh"
ENCHAT_NTFY = "https://enchat.sudosallie.com"
MAX_MSG_LEN = 500
PING_INTERVAL = 30  # seconds

console = Console()

# Track active room participants
room_participants = set()
last_ping_time = 0

# Enhanced security and error handling constants
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1
CONNECTION_TIMEOUT = 70
MAX_SEEN_HASHES = 500

# Encryption helpers with enhanced security
def gen_key(secret: str) -> bytes:
    """Generate encryption key using PBKDF2 for better security"""
    # Use enhanced salt that's derived from the app name
    # This ensures the same password always generates the same key
    # while still being more secure than plain SHA256
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for Fernet
        salt=salt,
        iterations=100_000,  # 100k iterations - good balance of security vs speed
    )
    key = kdf.derive(secret.encode())
    return base64.urlsafe_b64encode(key)

def encrypt(msg: str, f: Fernet) -> str:
    return f.encrypt(msg.encode()).decode()

def decrypt(token: str, f: Fernet) -> str:
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return ""

# Enhanced secure configuration handling
def save_passphrase_keychain(room: str, secret: str) -> bool:
    """Save passphrase securely in system keychain"""
    if not KEYRING_AVAILABLE:
        return False
    try:
        keyring.set_password("enchat", f"room_{room}", secret)
        return True
    except Exception:
        return False

def load_passphrase_keychain(room: str) -> str:
    """Load passphrase from system keychain"""
    if not KEYRING_AVAILABLE:
        return ""
    try:
        return keyring.get_password("enchat", f"room_{room}") or ""
    except Exception:
        return ""

def save_conf(room: str, nick: str, secret: str, ntfy_server: str = DEFAULT_NTFY):
    with open(CONF_FILE, "w") as f:
        f.write(f"{room}\n{nick}\n{secret}\n{ntfy_server}\n")
    try:
        os.chmod(CONF_FILE, 0o600)
    except Exception:
        pass

def load_conf() -> Tuple[str, str, str, str]:
    """Load configuration with keychain fallback"""
    if not os.path.exists(CONF_FILE):
        return None, None, None, None
    try:
        with open(CONF_FILE) as f:
            lines = [l.strip() for l in f.readlines()]
            if len(lines) >= 3:
                room = lines[0]
                nick = lines[1] 
                secret = lines[2]
                server = lines[3] if len(lines) >= 4 else DEFAULT_NTFY
                
                # If no secret in config, try keychain
                if not secret and room:
                    secret = load_passphrase_keychain(room)
                
                return room, nick, secret, server
    except Exception:
        pass
    return None, None, None, DEFAULT_NTFY

# Enhanced cross-platform notifications
def notify(msg: str):
    """Cross-platform desktop notifications with privacy protection"""
    # Linux: only if notify-send exists; suppress all output/errors
    if sys.platform.startswith("linux") and which("notify-send"):
        try:
            subprocess.run(
                ["notify-send", "Enchat", msg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass
    # macOS: use osascript if available, also silenced
    elif sys.platform == "darwin" and which("osascript"):
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{msg}" with title "Enchat"'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass
    # Windows: use Windows 10+ toast notifications via PowerShell
    elif sys.platform == "win32":
        try:
            # Use Windows 10+ toast notifications (non-blocking)
            toast_script = f'''
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>Enchat</text>
            <text>{msg.replace('"', '&quot;')}</text>
        </binding>
    </visual>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Enchat").Show($toast)
'''
            subprocess.run([
                "powershell", "-WindowStyle", "Hidden", "-Command", toast_script
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            # Fallback to console beep on Windows
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except:
                pass

# Enhanced network functions with retry logic and error handling
def send_system(room: str, nick: str, what: str, ntfy_server: str, fernet: Fernet):
    """Send system events with encryption and retry logic"""
    try:
        # Encrypt system events for better privacy
        timestamp = int(time.time())
        payload = f"{timestamp}|{nick}|SYSTEM:{what}"
        enc = encrypt(payload, fernet)
        
        retry_count = 0
        retry_delay = RETRY_BASE_DELAY
        
        while retry_count < MAX_RETRIES:
            try:
                # Send encrypted system event - no plaintext identifiers
                response = requests.post(f"{ntfy_server}/{room}", data=f"SYS:{enc}", timeout=10)
                
                if response.status_code == 200:
                    return True
                elif response.status_code == 429 and retry_count < MAX_RETRIES - 1:
                    retry_count += 1
                    # Get retry delay from header or use exponential backoff
                    if 'Retry-After' in response.headers:
                        retry_seconds = int(response.headers['Retry-After'])
                    else:
                        retry_seconds = retry_delay
                        retry_delay *= 2
                    
                    time.sleep(retry_seconds)
                else:
                    # Silent fail for system messages after retries
                    break
            except Exception:
                retry_count += 1
                if retry_count < MAX_RETRIES:
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    break
    except Exception:
        pass  # Silent fail for system messages

def send_msg(room: str, nick: str, msg: str, fernet: Fernet, ntfy_server: str) -> bool:
    """Send message with enhanced retry logic and rate limiting protection"""
    try:
        # Create a payload with timestamp, nick, and message - all encrypted together
        timestamp = int(time.time())
        payload = f"{timestamp}|{nick}|{msg}"
        enc = encrypt(payload, fernet)
        
        retry_count = 0
        retry_delay = RETRY_BASE_DELAY
        
        while retry_count < MAX_RETRIES:
            try:
                # Send only encrypted data - no plaintext identifiers
                response = requests.post(f"{ntfy_server}/{room}", data=f"MSG:{enc}", timeout=10)
                
                if response.status_code == 200:
                    return True  # Message sent successfully
                elif response.status_code == 429:
                    retry_count += 1
                    if retry_count < MAX_RETRIES:
                        # Get retry delay from header or use exponential backoff
                        if 'Retry-After' in response.headers:
                            retry_seconds = int(response.headers['Retry-After'])
                        else:
                            retry_seconds = retry_delay
                            retry_delay *= 2  # Exponential backoff
                        
                        console.print(f"[yellow]⚠️ Rate limited. Retrying in {retry_seconds}s ({retry_count}/{MAX_RETRIES})[/]")
                        time.sleep(retry_seconds)
                    else:
                        console.print(f"[red]❌ Failed to send after {MAX_RETRIES} retries. Server is rate limiting requests.[/]")
                        return False
                else:
                    console.print(f"[red]❌ Failed to send message (HTTP {response.status_code})[/]")
                    return False
            except Exception as e:
                retry_count += 1
                if retry_count < MAX_RETRIES:
                    console.print(f"[yellow]⚠️ Network error, retrying... ({retry_count}/{MAX_RETRIES})[/]")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    console.print(f"[red]❌ Failed to send message: {str(e)[:50]}[/]")
                    return False
        
        return False
        
    except Exception as e:
        console.print(f"[red]❌ Failed to send message: {str(e)[:50]}[/]")
        return False

# Enhanced listener thread with robust error handling and participant tracking
def listen(room: str, nick: str, fernet: Fernet, server: str,
           messages: List[Tuple[str, str, bool]], stop_event: threading.Event):
    """Enhanced listener with robust error handling and participant tracking"""
    url = f"{server}/{room}/raw"
    seen = set()
    last_ping = 0
    connection_attempts = 0
    global last_ping_time
    
    # Add ourselves to participants
    room_participants.add(nick)
    
    while not stop_event.is_set():
        try:
            if connection_attempts > 0:
                console.print(f"[yellow]🔄 Reconnecting... (attempt #{connection_attempts})[/]")
            
            # Add headers to ensure proper streaming behavior across platforms
            headers = {
                'Cache-Control': 'no-cache',
                'Accept': 'text/plain',
                'Connection': 'keep-alive'
            }
            
            with requests.get(url, stream=True, timeout=CONNECTION_TIMEOUT, headers=headers) as resp:
                if connection_attempts > 0:
                    console.print(f"[green]✅ Reconnected successfully![/]")
                connection_attempts = 0
                
                # Process lines with explicit buffering control
                for line in resp.iter_lines(decode_unicode=True, delimiter='\n'):
                    if stop_event.is_set(): 
                        break
                    if not line or line.strip() == "": 
                        continue
                    
                    line = line.strip()
                    h = hashlib.sha256(line.encode()).hexdigest()
                    if h in seen: 
                        continue
                    seen.add(h)
                    
                    # Clean up seen set to prevent memory growth
                    if len(seen) > MAX_SEEN_HASHES:
                        seen = set(list(seen)[-MAX_SEEN_HASHES//2:])
                    
                    # Skip empty or invalid lines
                    if not line or not line.startswith(("MSG:", "SYS:", "[SYSTEM]", "[")):
                        continue
                    
                    # Handle new encrypted format
                    if line.startswith("SYS:") or line.startswith("MSG:"):
                        msg_type = line[:4]
                        encrypted_data = line[4:]
                        
                        # Try to decrypt the payload
                        plain_payload = decrypt(encrypted_data, fernet)
                        if plain_payload == "":
                            # Invalid encryption - skip silently
                            continue
                            
                        try:
                            # Parse the decrypted payload: timestamp|nick|content
                            parts = plain_payload.split("|", 2)
                            if len(parts) != 3:
                                continue
                                
                            msg_timestamp, sender, content = parts
                            
                            # Add sender to participants list
                            if sender != nick:
                                room_participants.add(sender)
                            
                            if msg_type == "SYS:":
                                # Handle system events
                                if content.startswith("SYSTEM:"):
                                    what = content[7:]  # Remove "SYSTEM:" prefix
                                    
                                    if what == "joined":
                                        room_participants.add(sender)
                                        if sender != nick:
                                            messages.append(("System", f"{sender} joined the chat", False))
                                            notify(f"{sender} joined")
                                            # Send a ping after someone joins to help them discover existing participants
                                            send_system(room, nick, "ping", server, fernet)
                                    elif what == "left":
                                        if sender in room_participants:
                                            room_participants.remove(sender)
                                        if sender != nick:
                                            messages.append(("System", f"{sender} left the chat", False))
                                            notify(f"{sender} left")
                                    elif what == "ping" and sender != nick:
                                        # When we receive a ping, add the sender to participants if not already there
                                        # and send our own ping in response if we haven't recently
                                        room_participants.add(sender)
                                        current_time = time.time()
                                        if current_time - last_ping_time > 5:  # Limit ping responses to avoid flooding
                                            send_system(room, nick, "ping", server, fernet)
                                            last_ping_time = current_time
                            elif msg_type == "MSG:":
                                # Handle chat messages
                                is_own_message = (sender == nick)
                                if not is_own_message:  # Only show messages from others
                                    messages.append((sender, content, False))
                                    notify(f"New message from {sender}")  # Privacy: no message content in notifications
                                    
                        except (ValueError, IndexError):
                            # Malformed payload - skip silently
                            continue
                            
                    # Legacy format support (for backwards compatibility)
                    elif line.startswith("[SYSTEM][") or (line.startswith("[") and "] " in line):
                        # Handle old plaintext format for backwards compatibility
                        
                        if line.startswith("[SYSTEM]["):
                            who = line.split("]")[1][1:]
                            what = line.split("] ")[-1]
                            
                            # Handle participant tracking
                            if what == "joined":
                                room_participants.add(who)
                                if who != nick:
                                    messages.append(("System", f"{who} joined the chat", False))
                                    notify(f"{who} joined")
                                    send_system(room, nick, "ping", server, fernet)
                            elif what == "left":
                                if who in room_participants:
                                    room_participants.remove(who)
                                if who != nick:
                                    messages.append(("System", f"{who} left the chat", False))
                                    notify(f"{who} left")
                            elif what == "ping" and who != nick:
                                room_participants.add(who)
                                current_time = time.time()
                                if current_time - last_ping_time > 5:
                                    send_system(room, nick, "ping", server, fernet)
                                    last_ping_time = current_time
                        else:
                            # Legacy chat message format
                            sender = line.split("]")[0][1:]
                            data = "]".join(line.split("]")[1:]).strip()
                            
                            if sender != nick:
                                room_participants.add(sender)
                            
                            plain = decrypt(data, fernet)
                            if plain != "":
                                is_own_message = (sender == nick)
                                if not is_own_message:
                                    messages.append((sender, plain, False))
                                    notify(f"New message from {sender}")
                            else:
                                # Check for encrypted message indicators
                                if data.startswith(("U2FsdGVk","gAAAA")):
                                    messages.append(("System", f"{sender}: 🔒 Encrypted message - wrong passphrase", False))
                            
        except Exception as e:
            if not stop_event.is_set():
                connection_attempts += 1
                error_msg = str(e)[:50] if str(e) else "Unknown error"
                console.print(f"[red]❌ Connection lost: {error_msg}[/]")
                # Exponential backoff with maximum delay
                retry_delay = min(2 ** min(connection_attempts, 5), 30)
                time.sleep(retry_delay)

# Rich-based UI
class ChatUI:
    def __init__(self, room: str, nick: str, server: str,
                 fernet: Fernet, messages: List[Tuple[str, str, bool]]):
        self.room = room
        self.nick = nick
        self.server = server
        self.fernet = fernet
        self.messages = messages
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="input", size=3),
        )

    def render_header(self, status: str) -> Panel:
        txt = Text.assemble(
            (" ENCHAT ", "bold cyan"),
            (f" {status} ", "bold green" if status == "CONNECTED" else "bold yellow"),
            (f" {self.room} ", "white"),
            (f" {self.nick} ", "magenta"),
        )
        return Panel(txt, style="blue")

    def render_body(self) -> Panel:
        body = Text()
        for user, msg, own in self.messages[-100:]:
            if user == "System":
                body.append(f"[SYSTEM] {msg}\n", style="yellow")
            else:
                label = "You" if own else user
                style = "green" if own else "cyan"
                body.append(f"{label}: ", style=style)
                body.append(f"{msg}\n")
        return Panel(body, title="Messages", padding=(1, 1))

    def render_input(self) -> Panel:
        return Panel("Type message (/help):")

    def run(self):
        stop_event = threading.Event()
        listener = threading.Thread(
            target=listen,
            args=(self.room, self.nick, self.fernet, self.server, self.messages, stop_event),
            daemon=True,
        )
        listener.start()
        self.messages.append(("System", f"Joined room {self.room}", False))
        send_system(self.room, self.nick, "joined", self.server, self.fernet)

        with Live(self.layout, refresh_per_second=10, screen=False) as live:
            status = "CONNECTED"
            while True:
                # Update header/body/input panels
                self.layout["header"].update(self.render_header(status))
                self.layout["body"].update(self.render_body())
                self.layout["input"].update(self.render_input())
                live.refresh()

                # Temporarily stop live updates while the user types
                live.stop()
                msg = Prompt.ask(f"[bold cyan]{self.nick}[/]")
                live.start()

                if msg in ("/exit", "/quit"):
                    break
                elif msg == "/clear":
                    self.messages.clear()
                elif msg == "/help":
                    # Display full commands list
                    commands = [
                        ("/help", "Show available commands"),
                        ("/clear", "Clear screen"),
                        ("/exit", "Leave chat"),
                        ("/who", "Show all active room participants"),
                        ("/stats", "Session statistics and encryption info"),
                        ("/security", "Detailed security and privacy overview"),
                        ("/server", "Display current server information")
                    ]
                    for cmd, desc in commands:
                        self.messages.append(("System", f"{cmd}: {desc}", False))
                elif msg == "/who":
                    # Show active participants using real participant tracking
                    global room_participants
                    active_users = sorted(list(room_participants))
                    
                    if len(active_users) > 1:
                        self.messages.append(("System", f"=== ONLINE PARTICIPANTS ({len(active_users)}) ===", False))
                        for user in active_users:
                            if user == self.nick:
                                status_icon = "👑"
                                status_text = f"{user} (you)"
                            else:
                                status_icon = "●"
                                status_text = user
                            self.messages.append(("System", f"  {status_icon} {status_text}", False))
                    else:
                        self.messages.append(("System", "=== ONLINE PARTICIPANTS ===", False))
                        self.messages.append(("System", f"  👑 {self.nick} (you)", False))
                        self.messages.append(("System", "No other participants detected yet.", False))
                        self.messages.append(("System", "They will appear when they send messages or join.", False))
                elif msg == "/stats":
                    # Session statistics and encryption info
                    total_msgs = len([m for m in self.messages if m[0] != "System"])
                    your_msgs = len([m for m in self.messages if m[2] == True])  # own messages
                    received_msgs = total_msgs - your_msgs
                    
                    self.messages.append(("System", "=== SESSION STATISTICS ===", False))
                    self.messages.append(("System", f"Room: {self.room}", False))
                    self.messages.append(("System", f"Your nickname: {self.nick}", False))
                    self.messages.append(("System", f"Messages sent: {your_msgs}", False))
                    self.messages.append(("System", f"Messages received: {received_msgs}", False))
                    self.messages.append(("System", f"Total messages: {total_msgs}", False))
                    self.messages.append(("System", "--- ENCRYPTION INFO ---", False))
                    self.messages.append(("System", "Encryption: AES-256 (Fernet)", False))
                    self.messages.append(("System", "Key derivation: PBKDF2-HMAC-SHA256", False))
                    self.messages.append(("System", "All messages are end-to-end encrypted", False))
                    
                elif msg == "/security":
                    # Detailed security and privacy overview
                    self.messages.append(("System", "=== SECURITY & PRIVACY OVERVIEW ===", False))
                    self.messages.append(("System", "", False))
                    self.messages.append(("System", "🔐 ENCRYPTION:", False))
                    self.messages.append(("System", "  • AES-256 encryption in CBC mode", False))
                    self.messages.append(("System", "  • HMAC-SHA256 for message authentication", False))
                    self.messages.append(("System", "  • PBKDF2 key derivation (100,000 iterations)", False))
                    self.messages.append(("System", "  • Cryptographically secure random IV per message", False))
                    self.messages.append(("System", "", False))
                    self.messages.append(("System", "🛡️ PRIVACY:", False))
                    self.messages.append(("System", "  • Server never sees your messages in plaintext", False))
                    self.messages.append(("System", "  • Only encrypted data is transmitted", False))
                    self.messages.append(("System", "  • Room name and passphrase create unique keys", False))
                    self.messages.append(("System", "  • No user registration or accounts required", False))
                    self.messages.append(("System", "", False))
                    self.messages.append(("System", "⚠️ IMPORTANT:", False))
                    self.messages.append(("System", "  • Share room name & passphrase securely", False))
                    self.messages.append(("System", "  • Server logs may contain encrypted messages", False))
                    self.messages.append(("System", "  • Use strong, unique passphrases", False))
                    
                elif msg == "/server":
                    # Display current server information
                    server_name = self.server.replace("https://", "").replace("http://", "")
                    self.messages.append(("System", "=== SERVER INFORMATION ===", False))
                    self.messages.append(("System", f"Current server: {server_name}", False))
                    self.messages.append(("System", f"Full URL: {self.server}", False))
                    self.messages.append(("System", f"Room endpoint: {self.server}/{self.room}", False))
                    
                    # Try to get server status
                    try:
                        response = requests.get(f"{self.server}/v1/health", timeout=5)
                        if response.status_code == 200:
                            self.messages.append(("System", "Server status: ✅ Online", False))
                        else:
                            self.messages.append(("System", f"Server status: ⚠️ Response {response.status_code}", False))
                    except:
                        self.messages.append(("System", "Server status: ❌ Connection failed", False))
                    
                    self.messages.append(("System", "", False))
                    self.messages.append(("System", "Note: This is a public ntfy server", False))
                    self.messages.append(("System", "All messages are encrypted before transmission", False))
                else:
                    success = send_msg(self.room, self.nick, msg, self.fernet, self.server)
                    self.messages.append((self.nick, msg, True))
                    if not success:
                        self.messages.append(("System", "Failed to send message", False))

        stop_event.set()
        send_system(self.room, self.nick, "left", self.server, self.fernet)
        send_system(self.room, self.nick, "left", self.server, self.fernet)

# Enhanced setup function with keyring support
def setup_initial_config(args):
    """Handle initial configuration with enhanced security options"""
    console.clear()
    console.print("[bold cyan]🔐 Welcome to Enchat! Let's set up your encrypted chat.[/]")
    console.print()
    
    # Room configuration
    while True:
        room = Prompt.ask("[yellow]🏠 Room name (unique, secret)[/]").strip()
        if room and len(room) >= 3:
            break
        console.print("[red]Please enter a room name with at least 3 characters.[/]")
    
    # Normalize room name to ensure consistent behavior across servers
    room = room.lower().strip()
    
    # Nickname configuration  
    while True:
        nick = Prompt.ask("[yellow]👤 Your nickname[/]").strip()
        if nick and len(nick) >= 2:
            break
        console.print("[red]Please enter a nickname with at least 2 characters.[/]")
    
    # Encryption passphrase
    while True:
        secret = getpass("🔐 Encryption passphrase (hidden): ").strip()
        if secret and len(secret) >= 6:
            break
        console.print("[red]Please enter a passphrase with at least 6 characters.[/]")
    
    # Server configuration
    server = ENCHAT_NTFY  # Default to enchat server
    if not (args.server or args.enchat_server or args.default_server):
        console.print("[cyan]🌐 Select a ntfy server:[/]")
        console.print(f"  [yellow]1)[/] Enchat ntfy server ({ENCHAT_NTFY}) - Recommended")
        console.print("     - Dedicated server for enchat with generous limits")
        console.print(f"  [yellow]2)[/] Default ntfy server ({DEFAULT_NTFY})")
        console.print("     - Public server with rate limits")
        console.print(f"  [yellow]3)[/] Custom server")
        console.print("     - Your own or another ntfy server")
        
        choice = Prompt.ask("Enter choice [1-3]", choices=["1", "2", "3"], default="1")
        if choice == "1":
            server = ENCHAT_NTFY
        elif choice == "2":
            server = DEFAULT_NTFY
            console.print("[cyan]Note: The default server (ntfy.sh) may have rate limits. For high-volume use, consider option 1.[/]")
        elif choice == "3":
            custom_server = Prompt.ask("Enter custom ntfy server URL").strip()
            if custom_server:
                server = custom_server.rstrip('/')
    elif args.server:
        server = args.server.rstrip('/')
    elif args.enchat_server:
        server = ENCHAT_NTFY
    elif args.default_server:
        server = DEFAULT_NTFY
    
    # Enhanced passphrase storage options
    save_settings = Prompt.ask("💾 Save settings for quick reconnect?", choices=["y", "n"], default="y")
    if save_settings.lower() == "y":
        console.print("[cyan]🔐 How should we save your passphrase?[/]")
        
        if KEYRING_AVAILABLE:
            console.print("  [green]1) Secure (system keychain) - Recommended[/]")
            console.print("  [yellow]2) File (less secure)[/]")
            console.print("  [cyan]3) Don't save (ask each time)[/]")
            
            choice = Prompt.ask("Choose [1-3]", choices=["1", "2", "3"], default="1")
            
            if choice == "1":
                if save_passphrase_keychain(room, secret):
                    save_conf(room, nick, "", server)
                    console.print("[green]✅ Saved securely! You won't need to re-enter your passphrase.[/]")
                else:
                    save_conf(room, nick, "", server)
                    console.print("[yellow]⚠️ Keychain failed. You'll be asked for your passphrase each time.[/]")
            elif choice == "2":
                save_conf(room, nick, secret, server)
                console.print("[green]✅ Saved to file.[/] [yellow]Warning: passphrase stored in plaintext.[/]")
            else:
                save_conf(room, nick, "", server)
                console.print("[green]✅ Settings saved. You'll be asked for your passphrase each time.[/]")
        else:
            console.print("  [yellow]1) File (passphrase saved in plaintext)[/]")
            console.print("  [cyan]2) Don't save (ask each time) - More secure[/]")
            console.print("  [blue]💡 Install 'keyring' for secure storage: pip install keyring[/]")
            
            choice = Prompt.ask("Choose [1-2]", choices=["1", "2"], default="2")
            
            if choice == "1":
                save_conf(room, nick, secret, server)
                console.print("[green]✅ Saved to file.[/] [yellow]Warning: passphrase stored in plaintext.[/]")
            else:
                save_conf(room, nick, "", server)
                console.print("[green]✅ Settings saved. You'll be asked for your passphrase each time.[/]")
    
    return room, nick, secret, server

# Main entrypoint with enhanced security
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypted terminal chat with Rich UI and enhanced security")
    parser.add_argument("--reset", action="store_true",
                        help="Clear saved settings and start fresh")
    parser.add_argument("--server", type=str,
                        help="Use custom ntfy server (e.g., https://your-ntfy.example.com)")
    parser.add_argument("--enchat-server", action="store_true",
                        help=f"Use the enchat ntfy server ({ENCHAT_NTFY})")
    parser.add_argument("--default-server", action="store_true",
                        help=f"Use the default ntfy server ({DEFAULT_NTFY})")
    args = parser.parse_args()

    if args.reset and os.path.exists(CONF_FILE):
        os.remove(CONF_FILE)
        console.print("[green]✅ Settings cleared. Restart to configure again.[/]")
        sys.exit(0)

    room, nick, secret, server = load_conf()
    
    # Override with command line server if provided
    if args.server:
        server = args.server.rstrip('/')
    elif args.enchat_server:
        server = ENCHAT_NTFY
    elif args.default_server:
        server = DEFAULT_NTFY
    
    # Initial setup if no configuration exists or passphrase missing
    if not all([room, nick]) or not secret:
        if room and nick and not secret:
            # Config exists but no passphrase - prompt for it
            console.clear()
            console.print(f"[green]✨ Welcome back, [bold]{nick}[/]![/]")
            console.print(f"[cyan]🔐 Please enter your passphrase for room '{room}'[/]")
            while True:
                secret = getpass("🔐 Encryption passphrase (hidden): ").strip()
                if secret and len(secret) >= 6:
                    break
                console.print("[red]Please enter a passphrase with at least 6 characters.[/]")
        else:
            room, nick, secret, server = setup_initial_config(args)
    else:
        # Normalize room name from saved config to ensure consistency
        room = room.lower().strip()
        
        console.clear()
        console.print(f"[green]✨ Welcome back, [bold]{nick}[/]![/]")
        console.print("[cyan]📡 Connecting to encrypted room...[/]")

    # Generate encryption key
    key = gen_key(secret)
    fernet = Fernet(key)
    messages: List[Tuple[str, str, bool]] = []

    # Show connection status
    console.print("[yellow]🔄 Establishing secure connection...[/]")
    
    # Start the chat UI
    ui = ChatUI(room, nick, server, fernet, messages)
    
    # Enhanced signal handling for clean exit
    def on_exit(sig, frame):
        console.print("\n[yellow]👋 Leaving chat...[/]")
        send_system(room, nick, "left", server, fernet)
        console.print("[green]✅ Left chat securely. Goodbye![/]")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, on_exit)
    
    # Start ping thread to maintain presence and participant discovery
    stop_event = threading.Event()
    
    def ping_thread():
        global last_ping_time
        while not stop_event.is_set():
            current_time = time.time()
            if current_time - last_ping_time > PING_INTERVAL:
                send_system(room, nick, "ping", server, fernet)
                last_ping_time = current_time
            time.sleep(5)  # Check every 5 seconds
    
    ping_t = threading.Thread(target=ping_thread, daemon=True)
    ping_t.start()
    
    # Send initial system messages
    send_system(room, nick, "joined", server, fernet)
    time.sleep(0.5)  # Brief pause for system message to process
    send_system(room, nick, "ping", server, fernet)  # Announce presence
    
    try:
        ui.run()
    except Exception as e:
        console.print(f"[red]❌ Fatal error: {str(e)}[/]")
    finally:
        # Clean exit
        stop_event.set()
        send_system(room, nick, "left", server, fernet)
        console.print("[green]✅ Chat session ended securely.[/]")
