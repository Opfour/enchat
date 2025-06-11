#!/usr/bin/env python3
import os
import sys
import time
import signal
import base64
import hashlib
import threading
import argparse
import requests
from getpass import getpass
from colorama import init, Fore, Style, Back
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from shutil import which
import subprocess
from datetime import datetime

# Try to import keyring for secure passphrase storage
try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

init(autoreset=True)
CONF_FILE = os.path.expanduser("~/.enchat.conf")
DEFAULT_NTFY_SERVER = "https://ntfy.sh"
ENCHAT_NTFY_SERVER = "https://enchat.sudosallie.com"

# Enhanced UI Constants
BORDER_CHAR = "─"
CORNER_CHAR = "┌┐└┘"
SIDE_CHAR = "│"
MAX_MESSAGE_LENGTH = 500
STATUS_CONNECTED = "🟢"
STATUS_CONNECTING = "🟡"
STATUS_DISCONNECTED = "🔴"

class ChatUI:
    def __init__(self):
        self.terminal_width = os.get_terminal_size().columns
        self.status = STATUS_CONNECTING
        
    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")
    
    def print_header(self):
        width = self.terminal_width
        header = "ENCRYPTED TERMINAL CHAT"
        padding = (width - len(header) - 2) // 2
        
        print(Fore.CYAN + Style.BRIGHT + "┌" + "─" * (width - 2) + "┐")
        print("│" + " " * padding + header + " " * (width - len(header) - padding - 2) + "│")
        print("└" + "─" * (width - 2) + "┘" + Style.RESET_ALL)
        print()
    
    def print_status_bar(self, room, nick, ntfy_server):
        width = self.terminal_width
        server_display = ntfy_server.replace("https://", "").replace("http://", "")
        status_text = f"{self.status} {room} | {nick} | {server_display}"
        
        if len(status_text) > width - 4:
            status_text = status_text[:width - 7] + "..."
        
        padding = width - len(status_text) - 2
        print(Fore.BLUE + "┌" + "─" * (width - 2) + "┐")
        print("│" + status_text + " " * padding + "│" + Style.RESET_ALL)
        print(Fore.BLUE + "└" + "─" * (width - 2) + "┘" + Style.RESET_ALL)
    
    def print_system_message(self, msg, msg_type="info"):
        timestamp = self.get_timestamp()
        
        if msg_type == "join":
            icon = "→"
            color = Fore.GREEN
        elif msg_type == "leave": 
            icon = "←"
            color = Fore.RED
        elif msg_type == "error":
            icon = "⚠"
            color = Fore.YELLOW
        else:
            icon = "ℹ"
            color = Fore.CYAN
            
        print(f"{Fore.BLACK + Style.BRIGHT}[{timestamp}]{Style.RESET_ALL} {color}{icon} {msg}{Style.RESET_ALL}")
    
    def print_user_message(self, user, msg, is_own=False):
        timestamp = self.get_timestamp()
        
        # Truncate long messages
        if len(msg) > MAX_MESSAGE_LENGTH:
            msg = msg[:MAX_MESSAGE_LENGTH - 3] + "..."
        
        if is_own:
            user_color = Fore.GREEN + Style.BRIGHT
            msg_color = Style.RESET_ALL
        else:
            user_color = Fore.MAGENTA + Style.BRIGHT  
            msg_color = Style.RESET_ALL
            
        # Format: [timestamp] username: message
        print(f"{Fore.BLACK + Style.BRIGHT}[{timestamp}]{Style.RESET_ALL} {user_color}{user}:{Style.RESET_ALL} {msg_color}{msg}")
    
    def print_connection_status(self, status, details=""):
        if status == "connecting":
            self.status = STATUS_CONNECTING
            self.print_system_message(f"Connecting to server... {details}", "info")
        elif status == "connected":
            self.status = STATUS_CONNECTED
            self.print_system_message(f"Connected successfully! {details}", "info")
        elif status == "disconnected":
            self.status = STATUS_DISCONNECTED
            self.print_system_message(f"Connection lost. {details}", "error")
        elif status == "reconnecting":
            self.status = STATUS_CONNECTING
            self.print_system_message(f"Reconnecting... {details}", "info")
    
    def print_input_prompt(self):
        return f"{Fore.GREEN + Style.BRIGHT}💬 > {Style.RESET_ALL}"
    
    def print_loading_animation(self, text, duration=2):
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        i = 0
        
        while time.time() - start_time < duration:
            frame = frames[i % len(frames)]
            print(f"\r{Fore.CYAN}{frame} {text}...{Style.RESET_ALL}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        print(f"\r{' ' * (len(text) + 10)}\r", end="")  # Clear the line

ui = ChatUI()

# Track active room participants
room_participants = set()
last_ping_time = 0
PING_INTERVAL = 30  # Send a ping every 30 seconds

def gen_key(secret: str) -> bytes:
    """Generate encryption key using PBKDF2 for better security"""
    # Use a static salt that's derived from the app name
    # This ensures the same password always generates the same key
    # while still being more secure than plain SHA256
    salt = hashlib.sha256(b"enchat_v2_static_salt").digest()[:16]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for Fernet
        salt=salt,
        iterations=100000,  # 100k iterations - good balance of security vs speed
    )
    key = kdf.derive(secret.encode())
    return base64.urlsafe_b64encode(key)

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

def save_conf(room: str, nick: str, secret: str, ntfy_server: str = DEFAULT_NTFY_SERVER):
    with open(CONF_FILE, "w") as f:
        f.write(f"{room}\n{nick}\n{secret}\n{ntfy_server}\n")

def load_conf():
    try:
        with open(CONF_FILE) as f:
            lines = [l.strip() for l in f.readlines()]
            if len(lines) >= 3:
                room = lines[0]
                nick = lines[1] 
                secret = lines[2]
                ntfy_server = lines[3] if len(lines) >= 4 else DEFAULT_NTFY_SERVER
                
                # If no secret in config, try keychain
                if not secret and room:
                    secret = load_passphrase_keychain(room)
                
                return room, nick, secret, ntfy_server
    except Exception:
        pass
    return None, None, None, DEFAULT_NTFY_SERVER

def notify(msg: str):
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

def encrypt_msg(msg: str, fernet: Fernet) -> str:
    return fernet.encrypt(msg.encode()).decode()

def decrypt_msg(token: str, fernet: Fernet) -> str or None:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return None

def listen(room: str, nick: str, fernet: Fernet, stop_event: threading.Event, ntfy_server: str):
    url = f"{ntfy_server}/{room}/raw"
    seen = set()
    connection_attempts = 0
    global last_ping_time
    
    # Add ourselves to participants
    room_participants.add(nick)
    
    while not stop_event.is_set():
        try:
            if connection_attempts > 0:
                ui.print_connection_status("reconnecting", f"Attempt #{connection_attempts}")
            
            with requests.get(url, stream=True, timeout=70) as resp:
                if connection_attempts > 0:
                    ui.print_connection_status("connected", "Reconnected successfully")
                connection_attempts = 0
                
                for line in resp.iter_lines():
                    if stop_event.is_set(): break
                    if not line: continue
                    line = line.decode()
                    h = hashlib.sha256(line.encode()).hexdigest()
                    if h in seen: continue
                    seen.add(h)
                    if len(seen) > 500:
                        seen = set(list(seen)[-250:])
                    
                    # System events
                    if line.startswith("[SYSTEM]["):
                        who = line.split("]")[1][1:]
                        what = line.split("] ")[-1]
                        
                        # Handle participant tracking
                        if what == "joined":
                            room_participants.add(who)
                            if who != nick:
                                ui.print_system_message(f"{who} joined the chat", "join")
                                notify(f"{who} joined")
                                # Send a ping after someone joins to help them discover existing participants
                                send_system(room, nick, "ping", ntfy_server)
                        elif what == "left":
                            if who in room_participants:
                                room_participants.remove(who)
                            if who != nick:
                                ui.print_system_message(f"{who} left the chat", "leave")
                                notify(f"{who} left")
                        elif what == "ping" and who != nick:
                            # When we receive a ping, add the sender to participants if not already there
                            # and send our own ping in response if we haven't recently
                            room_participants.add(who)
                            current_time = time.time()
                            if current_time - last_ping_time > 5:  # Limit ping responses to avoid flooding
                                send_system(room, nick, "ping", ntfy_server)
                                last_ping_time = current_time
                        continue
                    
                    # Chat messages
                    if not line.startswith("[") or "] " not in line:
                        continue
                    sender = line.split("]")[0][1:]
                    data   = "]".join(line.split("]")[1:]).strip()
                    
                    # Add message sender to participants list
                    if sender != nick:
                        room_participants.add(sender)
                    
                    plain = decrypt_msg(data, fernet)
                    if plain is not None:
                        is_own_message = (sender == nick)
                        if not is_own_message:  # Only show messages from others
                            ui.print_user_message(sender, plain, is_own=False)
                            notify(f"New message from {sender}")  # Privacy: no message content in notifications
                    else:
                        if data.startswith(("U2FsdGVk","gAAAA")):
                            ui.print_user_message(sender, "[🔒 Encrypted message - wrong passphrase]")
                            
        except Exception as e:
            if not stop_event.is_set():
                connection_attempts += 1
                ui.print_connection_status("disconnected", f"({str(e)[:50]})")
                time.sleep(min(2 ** min(connection_attempts, 5), 30))  # Exponential backoff

def send_msg(room: str, msg: str, nick: str, fernet: Fernet, ntfy_server: str):
    try:
        enc = encrypt_msg(msg, fernet)
        max_retries = 3
        retry_count = 0
        retry_delay = 1
        
        while retry_count < max_retries:
            response = requests.post(f"{ntfy_server}/{room}", data=f"[{nick}] {enc}", timeout=10)
            
            if response.status_code == 200:
                return True  # Message sent successfully
            elif response.status_code == 429:
                retry_count += 1
                if retry_count < max_retries:
                    # Get retry delay from header or use exponential backoff
                    if 'Retry-After' in response.headers:
                        retry_seconds = int(response.headers['Retry-After'])
                    else:
                        retry_seconds = retry_delay
                        retry_delay *= 2  # Exponential backoff
                    
                    ui.print_system_message(f"Rate limited. Retrying in {retry_seconds}s ({retry_count}/{max_retries})", "error")
                    time.sleep(retry_seconds)
                else:
                    ui.print_system_message(f"Failed to send after {max_retries} retries. Server is rate limiting requests.", "error")
            else:
                ui.print_system_message(f"Failed to send message (HTTP {response.status_code})", "error")
                break
        
    except Exception as e:
        ui.print_system_message(f"Failed to send message: {str(e)[:50]}", "error")
        return False

def send_system(room: str, nick: str, what: str, ntfy_server: str):
    try:
        max_retries = 2
        retry_count = 0
        retry_delay = 1
        
        while retry_count < max_retries:
            response = requests.post(f"{ntfy_server}/{room}", data=f"[SYSTEM][{nick}] {what}", timeout=10)
            
            if response.status_code == 200:
                return True
            elif response.status_code == 429 and retry_count < max_retries - 1:
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
        pass  # Silent fail for system messages

def setup_initial_config(args):
    """Handle initial configuration with enhanced UI"""
    os.system("clear")
    ui.print_header()
    
    print(f"{Fore.CYAN}Welcome to Enchat! Let's set up your encrypted chat.{Style.RESET_ALL}\n")
    
    # Room configuration
    while True:
        room = input(f"{Fore.YELLOW}🏠 Room name (unique, secret): {Style.RESET_ALL}").strip()
        if room and len(room) >= 3:
            break
        print(f"{Fore.RED}Please enter a room name with at least 3 characters.{Style.RESET_ALL}")
    
    # Normalize room name to ensure consistent behavior across servers
    room = room.lower().strip()
    
    # Nickname configuration  
    while True:
        nick = input(f"{Fore.YELLOW}👤 Your nickname: {Style.RESET_ALL}").strip()
        if nick and len(nick) >= 2:
            break
        print(f"{Fore.RED}Please enter a nickname with at least 2 characters.{Style.RESET_ALL}")
    
    # Encryption passphrase
    while True:
        secret = getpass(f"{Fore.YELLOW}🔐 Encryption passphrase (hidden): {Style.RESET_ALL}").strip()
        if secret and len(secret) >= 6:
            break
        print(f"{Fore.RED}Please enter a passphrase with at least 6 characters.{Style.RESET_ALL}")
    
    # Server configuration
    ntfy_server = DEFAULT_NTFY_SERVER
    if not (args.server or args.enchat_server or args.default_server):
        print(f"{Fore.CYAN}🌐 Select a ntfy server:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}1){Style.RESET_ALL} Default ntfy server ({DEFAULT_NTFY_SERVER})")
        print(f"     - Public server with rate limits")
        print(f"  {Fore.YELLOW}2){Style.RESET_ALL} Enchat ntfy server ({ENCHAT_NTFY_SERVER})")
        print(f"     - Dedicated server for enchat with more generous limits")
        print(f"  {Fore.YELLOW}3){Style.RESET_ALL} Custom server")
        print(f"     - Your own or another ntfy server")
        
        while True:
            server_choice = input(f"{Fore.YELLOW}Enter choice [1-3] (default: 1): {Style.RESET_ALL}").strip() or "1"
            if server_choice == "1":
                ntfy_server = DEFAULT_NTFY_SERVER
                print(f"{Fore.CYAN}Note: The default server (ntfy.sh) may have rate limits. For high-volume use, consider another option.{Style.RESET_ALL}")
                break
            elif server_choice == "2":
                ntfy_server = ENCHAT_NTFY_SERVER
                break
            elif server_choice == "3":
                custom_server = input(f"{Fore.YELLOW}Enter custom ntfy server URL: {Style.RESET_ALL}").strip()
                if custom_server:
                    ntfy_server = custom_server.rstrip('/')
                    break
                print(f"{Fore.RED}Please enter a valid server URL.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Please enter a number between 1 and 3.{Style.RESET_ALL}")
    elif args.server:
        ntfy_server = args.server.rstrip('/')
    elif args.enchat_server:
        ntfy_server = ENCHAT_NTFY_SERVER
    elif args.default_server:
        ntfy_server = DEFAULT_NTFY_SERVER
    
    # Simple passphrase storage options
    save_settings = input(f"{Fore.YELLOW}💾 Save settings for quick reconnect? [Y/n]: {Style.RESET_ALL}").strip() or "Y"
    if save_settings.lower().startswith("y"):
        print(f"{Fore.CYAN}🔐 How should we save your passphrase?{Style.RESET_ALL}")
        
        if KEYRING_AVAILABLE:
            print(f"  {Fore.GREEN}1) Secure (system keychain) - Recommended{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}2) File (less secure){Style.RESET_ALL}")
            print(f"  {Fore.CYAN}3) Don't save (ask each time){Style.RESET_ALL}")
            
            choice = input(f"{Fore.YELLOW}Choose [1-3]: {Style.RESET_ALL}").strip() or "1"
            
            if choice == "1":
                if save_passphrase_keychain(room, secret):
                    save_conf(room, nick, "", ntfy_server)
                    print(f"{Fore.GREEN}✅ Saved securely! You won't need to re-enter your passphrase.{Style.RESET_ALL}")
                else:
                    save_conf(room, nick, "", ntfy_server)
                    print(f"{Fore.YELLOW}⚠️  Keychain failed. You'll be asked for your passphrase each time.{Style.RESET_ALL}")
            elif choice == "2":
                save_conf(room, nick, secret, ntfy_server)
                print(f"{Fore.GREEN}✅ Saved to file. {Fore.YELLOW}Warning: passphrase stored in plaintext.{Style.RESET_ALL}")
            else:
                save_conf(room, nick, "", ntfy_server)
                print(f"{Fore.GREEN}✅ Settings saved. You'll be asked for your passphrase each time.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}1) File (passphrase saved in plaintext){Style.RESET_ALL}")
            print(f"  {Fore.CYAN}2) Don't save (ask each time) - More secure{Style.RESET_ALL}")
            print(f"  {Fore.BLUE}💡 Install 'keyring' for secure storage: pip install keyring{Style.RESET_ALL}")
            
            choice = input(f"{Fore.YELLOW}Choose [1-2] (default: 2): {Style.RESET_ALL}").strip() or "2"
            
            if choice == "1":
                save_conf(room, nick, secret, ntfy_server)
                print(f"{Fore.GREEN}✅ Saved to file. {Fore.YELLOW}Warning: passphrase stored in plaintext.{Style.RESET_ALL}")
            else:
                save_conf(room, nick, "", ntfy_server)
                print(f"{Fore.GREEN}✅ Settings saved. You'll be asked for your passphrase each time.{Style.RESET_ALL}")
    
    return room, nick, secret, ntfy_server

def main():
    parser = argparse.ArgumentParser(description="Encrypted terminal chat using ntfy")
    parser.add_argument("--reset", action="store_true",
                        help="Clear saved settings and start fresh")
    parser.add_argument("--server", type=str,
                        help="Use custom ntfy server (e.g., https://your-ntfy.example.com)")
    parser.add_argument("--enchat-server", action="store_true",
                        help=f"Use the enchat ntfy server ({ENCHAT_NTFY_SERVER})")
    parser.add_argument("--default-server", action="store_true",
                        help=f"Use the default ntfy server ({DEFAULT_NTFY_SERVER})")
    args = parser.parse_args()

    if args.reset and os.path.exists(CONF_FILE):
        os.remove(CONF_FILE)
        print(f"{Fore.GREEN}✅ Settings cleared. Restart to configure again.{Style.RESET_ALL}")
        sys.exit(0)

    room, nick, secret, ntfy_server = load_conf()
    
    # Override with command line server if provided
    if args.server:
        ntfy_server = args.server.rstrip('/')
    elif args.enchat_server:
        ntfy_server = ENCHAT_NTFY_SERVER
    elif args.default_server:
        ntfy_server = DEFAULT_NTFY_SERVER
    
    # Initial setup if no configuration exists or passphrase missing
    if not all([room, nick]) or not secret:
        if room and nick and not secret:
            # Config exists but no passphrase - prompt for it
            os.system("clear")
            ui.print_header()
            print(f"{Fore.GREEN}✨ Welcome back, {Style.BRIGHT}{nick}{Style.RESET_ALL}{Fore.GREEN}!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔐 Please enter your passphrase for room '{room}'{Style.RESET_ALL}")
            while True:
                secret = getpass(f"{Fore.YELLOW}🔐 Encryption passphrase (hidden): {Style.RESET_ALL}").strip()
                if secret and len(secret) >= 6:
                    break
                print(f"{Fore.RED}Please enter a passphrase with at least 6 characters.{Style.RESET_ALL}")
        else:
            room, nick, secret, ntfy_server = setup_initial_config(args)
    else:
        # Normalize room name from saved config to ensure consistency
        room = room.lower().strip()
        
        os.system("clear")
        ui.print_header()
        print(f"{Fore.GREEN}✨ Welcome back, {Style.BRIGHT}{nick}{Style.RESET_ALL}{Fore.GREEN}!{Style.RESET_ALL}")
        server_display = ntfy_server.replace("https://", "").replace("http://", "")
        print(f"{Fore.CYAN}📡 Connecting to room '{room}' via {server_display}...{Style.RESET_ALL}\n")

    key = gen_key(secret)
    fernet = Fernet(key)

    # Show connection status
    ui.print_connection_status("connecting", "Establishing secure connection...")
    ui.print_loading_animation("Connecting", 1)
    
    print()
    ui.print_status_bar(room, nick, ntfy_server)
    print()
    
    # Join the room
    ui.print_system_message(f"Joined room '{room}' • Type /exit to quit, /clear to clear screen", "info")
    send_system(room, nick, "joined", ntfy_server)
    
    # Start listening thread
    stop_event = threading.Event()
    t = threading.Thread(target=listen,
                         args=(room, nick, fernet, stop_event, ntfy_server),
                         daemon=True)
    t.start()
    
    # Set connection status to connected after starting listener
    time.sleep(0.5)
    ui.print_connection_status("connected", "Ready to chat!")
    
    # Send initial ping to announce presence to existing participants
    send_system(room, nick, "ping", ntfy_server)
    
    # Start ping thread to maintain presence
    def ping_thread():
        global last_ping_time
        while not stop_event.is_set():
            current_time = time.time()
            if current_time - last_ping_time > PING_INTERVAL:
                send_system(room, nick, "ping", ntfy_server)
                last_ping_time = current_time
            time.sleep(5)  # Check every 5 seconds
    
    ping_t = threading.Thread(target=ping_thread, daemon=True)
    ping_t.start()
    
    print()

    def on_exit(sig, frame):
        print(f"\n{Fore.YELLOW}👋 Leaving chat...{Style.RESET_ALL}")
        send_system(room, nick, "left", ntfy_server)
        ui.print_system_message("You left the chat. Goodbye!", "leave")
        stop_event.set()
        sys.exit(0)
    signal.signal(signal.SIGINT, on_exit)

    # Main chat loop
    while not stop_event.is_set():
        try:
            msg = input(ui.print_input_prompt())
        except (EOFError, KeyboardInterrupt):
            on_exit(None, None)
            
        if msg == "/exit":
            on_exit(None, None)
        elif msg == "/clear":
            # Cross-platform screen clearing
            if sys.platform == "win32":
                os.system("cls")
            else:
                os.system("clear")
            ui.print_header()
            ui.print_status_bar(room, nick, ntfy_server)
            print()
            continue
        elif msg == "/help":
            print(f"\n{Fore.CYAN}📖 Available commands:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}/exit{Style.RESET_ALL}  - Leave the chat")
            print(f"  {Fore.GREEN}/clear{Style.RESET_ALL} - Clear the screen") 
            print(f"  {Fore.GREEN}/help{Style.RESET_ALL}  - Show this help")
            print(f"  {Fore.GREEN}/who{Style.RESET_ALL}   - Show active room participants")
            print(f"  {Fore.GREEN}/server{Style.RESET_ALL} - Show current server information")
            print(f"  {Fore.GREEN}/ratelimit{Style.RESET_ALL} - Show information about rate limiting\n")
            continue
        elif msg == "/server":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            print(f"\n{Fore.CYAN}🌐 Server Information:{Style.RESET_ALL}")
            print(f"  • Current server: {ntfy_server}")
            if ntfy_server == DEFAULT_NTFY_SERVER:
                print(f"  • Type: Default public ntfy.sh server")
                print(f"  • Note: May have stricter rate limits")
            elif ntfy_server == ENCHAT_NTFY_SERVER:
                print(f"  • Type: Dedicated Enchat server")
                print(f"  • Note: More generous rate limits for chat")
            else:
                print(f"  • Type: Custom server")
            print(f"  • To change servers, restart enchat with one of these options:")
            print(f"    - Use default: --default-server")
            print(f"    - Use enchat: --enchat-server") 
            print(f"    - Use custom: --server URL")
            print()
            continue
        elif msg == "/ratelimit":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            print(f"\n{Fore.CYAN}⚠️ Rate Limiting Information:{Style.RESET_ALL}")
            print(f"  • The ntfy.sh public server has rate limits to prevent abuse")
            print(f"  • If you hit a rate limit (HTTP 429), the app will automatically retry")
            print(f"  • Tips to avoid rate limits:")
            print(f"    - Wait a few seconds between messages")
            print(f"    - Use a unique room name that others are unlikely to use")
            print(f"    - Consider using the enchat server (restart with --enchat-server)")
            print(f"    - Or run your own ntfy server for high-volume use")
            print(f"      See: https://docs.ntfy.sh/install/")
            print()
            continue
        elif msg == "/who":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            
            # Create an encrypted copy of the participant list
            encrypted_participants = []
            for participant in sorted(room_participants):
                encrypted_participants.append(encrypt_msg(participant, fernet))
            
            # Display participants locally
            count = len(room_participants)
            print(f"\n{Fore.CYAN}👥 Room participants ({count}):{Style.RESET_ALL}")
            for participant in sorted(room_participants):
                if participant == nick:
                    print(f"  {Fore.GREEN}{participant} (you){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}{participant}{Style.RESET_ALL}")
            print()
            continue
        elif msg.strip():
            if len(msg) > MAX_MESSAGE_LENGTH:
                ui.print_system_message(f"Message too long ({len(msg)}/{MAX_MESSAGE_LENGTH} characters)", "error")
                continue
            # Clear the entire input line using ANSI escape codes
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            ui.print_user_message(nick, msg, is_own=True)
            send_msg(room, msg, nick, fernet, ntfy_server)

if __name__ == "__main__":
    main()
