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

# Enhanced UI Unicode (with ASCII fallback)
try:
    # Test if terminal supports Unicode box drawing
    print("╔", end="", flush=True)
    print("\r", end="", flush=True)  # Clear the test character
    BOX_CHARS = {
        'top_left': '╔', 'top_right': '╗', 'bottom_left': '╚', 'bottom_right': '╝',
        'horizontal': '═', 'vertical': '║', 'cross': '╬', 'tee_down': '╦', 'tee_up': '╩',
        'light_horizontal': '─', 'light_vertical': '│', 'light_cross': '┼'
    }
    UNICODE_SUPPORT = True
except:
    # Fallback to ASCII
    BOX_CHARS = {
        'top_left': '+', 'top_right': '+', 'bottom_left': '+', 'bottom_right': '+',
        'horizontal': '=', 'vertical': '|', 'cross': '+', 'tee_down': '+', 'tee_up': '+',
        'light_horizontal': '-', 'light_vertical': '|', 'light_cross': '+'
    }
    UNICODE_SUPPORT = False

class ChatUI:
    def __init__(self):
        self.terminal_width = max(80, os.get_terminal_size().columns)  # Minimum 80 chars
        self.terminal_height = max(24, os.get_terminal_size().lines)   # Minimum 24 rows
        self.status = STATUS_CONNECTING
        self.message_count = 0
        self.start_time = time.time()
        self.typing_users = set()
        self.last_activity = time.time()
        self.sidebar_width = min(25, self.terminal_width // 4)  # Adaptive sidebar
        self.main_width = self.terminal_width - self.sidebar_width - 1
        self.user_colors = {}  # Cache for consistent user colors
        self.color_palette = [
            Fore.MAGENTA, Fore.CYAN, Fore.YELLOW, Fore.GREEN, 
            Fore.BLUE, Fore.RED, Fore.WHITE
        ]
        
    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S")
    
    def get_user_color(self, username):
        """Get consistent color for a user"""
        if username not in self.user_colors:
            color_index = len(self.user_colors) % len(self.color_palette)
            self.user_colors[username] = self.color_palette[color_index]
        return self.user_colors[username]
    
    def get_uptime(self):
        """Get formatted uptime"""
        uptime = int(time.time() - self.start_time)
        hours = uptime // 3600
        minutes = (uptime % 3600) // 60
        seconds = uptime % 60
        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def print_modern_header(self, room, nick, ntfy_server):
        """Enhanced modern header with better visual hierarchy"""
        
        # Calculate dynamic width
        header_width = min(self.terminal_width, 100)
        
        # Brand section with enhanced styling
        brand_line = f"🔐 ENCHAT"
        tagline = "Encrypted Under The Radar Chat"
        
        # Center the brand
        brand_padding = (header_width - len(brand_line) - len(tagline) - 3) // 2
        
        print(f"\n{Back.BLACK}{Fore.CYAN}{'═' * header_width}{Style.RESET_ALL}")
        print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}{' ' * brand_padding}{Fore.CYAN + Style.BRIGHT}{brand_line}{Style.RESET_ALL} {Fore.CYAN}• {tagline}{Style.RESET_ALL}{' ' * (header_width - len(brand_line) - len(tagline) - brand_padding - 4)}{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Back.BLACK}{Fore.CYAN}{'╠' + '═' * (header_width - 2) + '╣'}{Style.RESET_ALL}")
        
        # Status line with enhanced design
        participants_count = len(room_participants)
        
        # Status indicators with better styling
        if self.status == "🟢":
            status_text = f"{Fore.GREEN + Style.BRIGHT}● ONLINE{Style.RESET_ALL}"
        elif self.status == "🟡":
            status_text = f"{Fore.YELLOW + Style.BRIGHT}● CONNECTING{Style.RESET_ALL}"
        else:
            status_text = f"{Fore.RED + Style.BRIGHT}● OFFLINE{Style.RESET_ALL}"
        
        # Build status components
        room_info = f"{Fore.GREEN + Style.BRIGHT}🏠 {room.upper()}{Style.RESET_ALL}"
        user_info = f"{Fore.BLUE + Style.BRIGHT}👤 {nick}{Style.RESET_ALL}"
        security_info = f"{Fore.RED + Style.BRIGHT}🔒 AES-256{Style.RESET_ALL}"
        
        # Status line with proper spacing
        status_content = f"║ {room_info}  •  {user_info}  •  {status_text}  •  {security_info}"
        status_padding = header_width - len(status_content.replace(Fore.GREEN + Style.BRIGHT, '').replace(Fore.BLUE + Style.BRIGHT, '').replace(Fore.RED + Style.BRIGHT, '').replace(Fore.YELLOW + Style.BRIGHT, '').replace(Style.RESET_ALL, '')) - 1
        
        print(f"{Back.BLACK}{Fore.CYAN}{status_content}{' ' * max(0, status_padding)}║{Style.RESET_ALL}")
        print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (header_width - 2) + '╝'}{Style.RESET_ALL}")
        print()
    
    def print_enhanced_header(self, room, nick, ntfy_server):
        """Legacy enhanced header - calls modern version"""
        self.print_modern_header(room, nick, ntfy_server)
    
    def print_header(self):
        """Legacy header for backwards compatibility"""
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
        
        # Enhanced system message styling
        if msg_type == "join":
            icon = "🎉"
            color = Fore.GREEN + Style.BRIGHT
            bg_color = Back.GREEN
            text_color = Fore.BLACK
        elif msg_type == "leave": 
            icon = "👋"
            color = Fore.RED + Style.BRIGHT
            bg_color = Back.RED
            text_color = Fore.WHITE
        elif msg_type == "error":
            icon = "⚠️"
            color = Fore.YELLOW + Style.BRIGHT
            bg_color = Back.YELLOW
            text_color = Fore.BLACK
        else:
            icon = "ℹ️"
            color = Fore.CYAN + Style.BRIGHT
            bg_color = Back.CYAN
            text_color = Fore.BLACK
        
        # Enhanced system message with better visual design
        print(f"  {bg_color}{text_color + Style.BRIGHT} {icon} SYSTEM {Style.RESET_ALL} {color}[{timestamp}]{Style.RESET_ALL} {msg}")
        print()
    
    def print_modern_message(self, user, msg, is_own=False, msg_type="normal"):
        """Enhanced message bubbles with better visual design"""
        timestamp = self.get_timestamp()
        self.message_count += 1
        
        # Truncate long messages
        if len(msg) > MAX_MESSAGE_LENGTH:
            msg = msg[:MAX_MESSAGE_LENGTH - 3] + "..."
        
        # Clean message design without background colors
        if is_own:
            # Your messages - right aligned with clean styling
            user_display = "You"
            accent_color = Fore.GREEN + Style.BRIGHT
            align_padding = "    "
            bubble_char = "▶"
        else:
            # Others' messages - left aligned with user-specific styling
            user_display = user
            accent_color = self.get_user_color(user) + Style.BRIGHT
            align_padding = ""
            bubble_char = "◀"
        
        # Special message types with clean styling
        if msg_type == "encrypted":
            accent_color = Fore.RED + Style.BRIGHT
            msg = f"🔒 {msg}"
            bubble_char = "🔐"
        elif msg_type == "system":
            accent_color = Fore.YELLOW + Style.BRIGHT
            user_display = "System"
            bubble_char = "⚙"
        
        # Enhanced header with better visual separation
        if is_own:
            header = f"{align_padding}{accent_color + Style.BRIGHT}{bubble_char} {user_display}{Style.RESET_ALL} {Fore.BLACK + Style.DIM}[{timestamp}]{Style.RESET_ALL}"
        else:
            header = f"{accent_color + Style.BRIGHT}{bubble_char} {user_display}{Style.RESET_ALL} {Fore.BLACK + Style.DIM}[{timestamp}]{Style.RESET_ALL}"
        
        print(header)
        
        # Enhanced message content with better word wrapping
        words = msg.split(' ')
        lines = []
        current_line = ""
        max_line_length = min(65, self.terminal_width - 12)
        
        for word in words:
            if len(current_line + word) <= max_line_length:
                current_line += word + " "
            else:
                if current_line:
                    lines.append(current_line.rstrip())
                current_line = word + " "
        if current_line:
            lines.append(current_line.rstrip())
        
        # Clean message content without background colors
        for i, line in enumerate(lines):
            if is_own:
                # Right-aligned messages with clean styling
                print(f"      {line}")
            else:
                # Left-aligned messages with clean styling  
                print(f"  {line}")
        
        print()  # Clean spacing between messages
    
    def print_rich_message(self, user, msg, is_own=False, msg_type="normal"):
        """Legacy rich message - calls modern version"""
        self.print_modern_message(user, msg, is_own, msg_type)
    
    def print_user_message(self, user, msg, is_own=False):
        """Always use modern message format"""
        self.print_modern_message(user, msg, is_own)
    
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
    
    def print_modern_input_area(self, current_input=""):
        """Enhanced input area with better visual design"""
        width = self.terminal_width
        char_count = len(current_input)
        
        # Enhanced input separator with gradient effect
        print(f"{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
        
        # Enhanced prompt with better visual hierarchy
        if char_count > MAX_MESSAGE_LENGTH * 0.9:  # Critical warning
            char_color = Fore.RED + Style.BRIGHT
            status_icon = "⚠"
        elif char_count > MAX_MESSAGE_LENGTH * 0.8:  # Warning
            char_color = Fore.YELLOW + Style.BRIGHT
            status_icon = "⚡"
        else:
            char_color = Fore.CYAN + Style.BRIGHT
            status_icon = "✓"
        
        # Enhanced character counter with status
        char_info = f"{char_color}{status_icon} {char_count}/{MAX_MESSAGE_LENGTH}{Style.RESET_ALL}"
        
        # Enhanced prompt line with better spacing
        prompt_content = f"💬 {Fore.WHITE + Style.BRIGHT}Type your message...{Style.RESET_ALL}"
        padding = width - len(prompt_content.replace(Fore.WHITE + Style.BRIGHT, '').replace(Style.RESET_ALL, '')) - len(char_info.replace(char_color, '').replace(Style.RESET_ALL, '')) - 6
        
        print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {prompt_content}{' ' * max(0, padding)}{char_info} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
    
    def print_enhanced_input_area(self, current_input=""):
        """Legacy input area - calls modern version"""
        self.print_modern_input_area(current_input)
    
    def print_input_prompt(self):
        """Modern, clean input prompt"""
        return f"{Fore.GREEN + Style.BRIGHT}→ {Style.RESET_ALL}"
    
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
            
            # Add headers to ensure proper streaming behavior across platforms
            headers = {
                'Cache-Control': 'no-cache',
                'Accept': 'text/plain',
                'Connection': 'keep-alive'
            }
            
            with requests.get(url, stream=True, timeout=70, headers=headers) as resp:
                if connection_attempts > 0:
                    ui.print_connection_status("connected", "Reconnected successfully")
                connection_attempts = 0
                
                # Process lines with explicit buffering control
                for line in resp.iter_lines(decode_unicode=True, delimiter='\n'):
                    if stop_event.is_set(): break
                    if not line or line.strip() == "": continue
                    
                    line = line.strip()
                    h = hashlib.sha256(line.encode()).hexdigest()
                    if h in seen: continue
                    seen.add(h)
                    if len(seen) > 500:
                        seen = set(list(seen)[-250:])
                    
                    # Skip empty or invalid lines
                    if not line or not line.startswith(("MSG:", "SYS:", "[SYSTEM]", "[")):
                        continue
                    
                    # Handle new encrypted format
                    if line.startswith("SYS:") or line.startswith("MSG:"):
                        msg_type = line[:4]
                        encrypted_data = line[4:]
                        
                        # Try to decrypt the payload
                        plain_payload = decrypt_msg(encrypted_data, fernet)
                        if plain_payload is None:
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
                                            ui.print_system_message(f"{sender} joined the chat", "join")
                                            notify(f"{sender} joined")
                                            # Send a ping after someone joins to help them discover existing participants
                                            send_system(room, nick, "ping", ntfy_server, fernet)
                                    elif what == "left":
                                        if sender in room_participants:
                                            room_participants.remove(sender)
                                        if sender != nick:
                                            ui.print_system_message(f"{sender} left the chat", "leave")
                                            notify(f"{sender} left")
                                    elif what == "ping" and sender != nick:
                                        # When we receive a ping, add the sender to participants if not already there
                                        # and send our own ping in response if we haven't recently
                                        room_participants.add(sender)
                                        current_time = time.time()
                                        if current_time - last_ping_time > 5:  # Limit ping responses to avoid flooding
                                            send_system(room, nick, "ping", ntfy_server, fernet)
                                            last_ping_time = current_time
                            elif msg_type == "MSG:":
                                # Handle chat messages
                                is_own_message = (sender == nick)
                                if not is_own_message:  # Only show messages from others
                                    ui.print_user_message(sender, content, is_own=False)
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
                                    ui.print_system_message(f"{who} joined the chat", "join")
                                    notify(f"{who} joined")
                                    send_system(room, nick, "ping", ntfy_server, fernet)
                            elif what == "left":
                                if who in room_participants:
                                    room_participants.remove(who)
                                if who != nick:
                                    ui.print_system_message(f"{who} left the chat", "leave")
                                    notify(f"{who} left")
                            elif what == "ping" and who != nick:
                                room_participants.add(who)
                                current_time = time.time()
                                if current_time - last_ping_time > 5:
                                    send_system(room, nick, "ping", ntfy_server, fernet)
                                    last_ping_time = current_time
                        else:
                            # Legacy chat message format
                            sender = line.split("]")[0][1:]
                            data = "]".join(line.split("]")[1:]).strip()
                            
                            if sender != nick:
                                room_participants.add(sender)
                            
                            plain = decrypt_msg(data, fernet)
                            if plain is not None:
                                is_own_message = (sender == nick)
                                if not is_own_message:
                                    ui.print_user_message(sender, plain, is_own=False)
                                    notify(f"New message from {sender}")
                            else:
                                if data.startswith(("U2FsdGVk","gAAAA")):
                                    if ui.terminal_width >= 100:
                                        ui.print_rich_message(sender, "Encrypted message - wrong passphrase", msg_type="encrypted")
                                    else:
                                        ui.print_user_message(sender, "[🔒 Encrypted message - wrong passphrase]")
                            
        except Exception as e:
            if not stop_event.is_set():
                connection_attempts += 1
                ui.print_connection_status("disconnected", f"({str(e)[:50]})")
                time.sleep(min(2 ** min(connection_attempts, 5), 30))  # Exponential backoff

def send_msg(room: str, msg: str, nick: str, fernet: Fernet, ntfy_server: str):
    try:
        # Create a payload with timestamp, nick, and message - all encrypted together
        timestamp = int(time.time())
        payload = f"{timestamp}|{nick}|{msg}"
        enc = encrypt_msg(payload, fernet)
        
        max_retries = 3
        retry_count = 0
        retry_delay = 1
        
        while retry_count < max_retries:
            # Send only encrypted data - no plaintext identifiers
            response = requests.post(f"{ntfy_server}/{room}", data=f"MSG:{enc}", timeout=10)
            
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

def send_system(room: str, nick: str, what: str, ntfy_server: str, fernet: Fernet):
    try:
        # Encrypt system events too for better privacy
        timestamp = int(time.time())
        payload = f"{timestamp}|{nick}|SYSTEM:{what}"
        enc = encrypt_msg(payload, fernet)
        
        max_retries = 2
        retry_count = 0
        retry_delay = 1
        
        while retry_count < max_retries:
            # Send encrypted system event - no plaintext identifiers
            response = requests.post(f"{ntfy_server}/{room}", data=f"SYS:{enc}", timeout=10)
            
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
    ui.print_header()  # Use legacy header during setup for simplicity
    
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
    ntfy_server = ENCHAT_NTFY_SERVER  # Default to enchat server
    if not (args.server or args.enchat_server or args.default_server):
        print(f"{Fore.CYAN}🌐 Select a ntfy server:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}1){Style.RESET_ALL} Enchat ntfy server ({ENCHAT_NTFY_SERVER}) - Recommended")
        print(f"     - Dedicated server for enchat with generous limits")
        print(f"  {Fore.YELLOW}2){Style.RESET_ALL} Default ntfy server ({DEFAULT_NTFY_SERVER})")
        print(f"     - Public server with rate limits")
        print(f"  {Fore.YELLOW}3){Style.RESET_ALL} Custom server")
        print(f"     - Your own or another ntfy server")
        
        while True:
            server_choice = input(f"{Fore.YELLOW}Enter choice [1-3] (default: 1): {Style.RESET_ALL}").strip() or "1"
            if server_choice == "1":
                ntfy_server = ENCHAT_NTFY_SERVER
                break
            elif server_choice == "2":
                ntfy_server = DEFAULT_NTFY_SERVER
                print(f"{Fore.CYAN}Note: The default server (ntfy.sh) may have rate limits. For high-volume use, consider option 1.{Style.RESET_ALL}")
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
            ui.print_enhanced_header(room, nick, ntfy_server)
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
        print(f"{Fore.GREEN}✨ Welcome back, {Style.BRIGHT}{nick}{Style.RESET_ALL}{Fore.GREEN}!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📡 Connecting to encrypted room...{Style.RESET_ALL}\n")

    key = gen_key(secret)
    fernet = Fernet(key)

    # Show connection status
    ui.print_connection_status("connecting", "Establishing secure connection...")
    ui.print_loading_animation("Connecting", 1)
    
    # Join the room
    ui.print_system_message(f"Joined room '{room}' • Type /exit to quit, /clear to clear screen", "info")
    send_system(room, nick, "joined", ntfy_server, fernet)
    
    # Start listening thread
    stop_event = threading.Event()
    t = threading.Thread(target=listen,
                         args=(room, nick, fernet, stop_event, ntfy_server),
                         daemon=True)
    t.start()
    
    # Set connection status to connected after starting listener
    time.sleep(0.5)
    ui.print_connection_status("connected", "Ready to chat!")
    
    # Now show the header with the correct connected status
    print()
    ui.print_enhanced_header(room, nick, ntfy_server)
    print()
    
    # Send initial ping to announce presence to existing participants
    send_system(room, nick, "ping", ntfy_server, fernet)
    
    # Start ping thread to maintain presence
    def ping_thread():
        global last_ping_time
        while not stop_event.is_set():
            current_time = time.time()
            if current_time - last_ping_time > PING_INTERVAL:
                send_system(room, nick, "ping", ntfy_server, fernet)
                last_ping_time = current_time
            time.sleep(5)  # Check every 5 seconds
    
    ping_t = threading.Thread(target=ping_thread, daemon=True)
    ping_t.start()
    
    print()

    def on_exit(sig, frame):
        print(f"\n{Fore.YELLOW}👋 Leaving chat...{Style.RESET_ALL}")
        send_system(room, nick, "left", ntfy_server, fernet)
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
            ui.print_enhanced_header(room, nick, ntfy_server)
            print()
            continue
        elif msg == "/help":
            width = ui.terminal_width
            print(f"\n{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {Fore.WHITE + Style.BRIGHT}📖  AVAILABLE COMMANDS{Style.RESET_ALL}{' ' * (width - 22)} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.CYAN}{'╠' + '═' * (width - 2) + '╣'}{Style.RESET_ALL}")
            
            commands = [
                ("/exit", "Leave chat and secure wipe", "🚪"),
                ("/clear", "Refresh interface", "🔄"),
                ("/who", "Show online users", "👥"),
                ("/stats", "Session statistics", "📊"),
                ("/security", "Security & privacy info", "🛡️"),
                ("/server", "Server information", "🌐")
            ]
            
            for cmd, desc, icon in commands:
                cmd_text = f"{icon} {Fore.GREEN + Style.BRIGHT}{cmd}{Style.RESET_ALL}"
                padding = width - len(f"{icon} {cmd}") - len(desc) - 8
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {cmd_text}{' ' * max(0, padding)}{desc} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")

            print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
            print()
            continue
        elif msg == "/security":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            width = ui.terminal_width
            
            print(f"\n{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
            header_text = "🛡️  SECURITY & PRIVACY OVERVIEW"
            header_padding = width - len(header_text) - 4
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {Fore.WHITE + Style.BRIGHT}{header_text}{Style.RESET_ALL}{' ' * header_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.CYAN}{'╠' + '═' * (width - 2) + '╣'}{Style.RESET_ALL}")
            
            # Encrypted section
            encrypted_title = f"{Fore.GREEN + Style.BRIGHT}✅ ENCRYPTED (Hidden from server/network):{Style.RESET_ALL}"
            title_padding = width - len("✅ ENCRYPTED (Hidden from server/network):") - 4
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {encrypted_title}{' ' * title_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            encrypted_items = [
                "• Message content",
                "• Usernames/nicknames",
                "• Timestamps", 
                "• Join/leave/ping events",
                "• All metadata"
            ]
            
            for item in encrypted_items:
                item_padding = width - len(item) - 7
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}   {item}{' ' * item_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}{' ' * (width - 2)} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            # Visible section
            visible_title = f"{Fore.YELLOW + Style.BRIGHT}⚠️  VISIBLE (But necessary for routing):{Style.RESET_ALL}"
            visible_title_padding = width - len("⚠️  VISIBLE (But necessary for routing):") - 4
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {visible_title}{' ' * visible_title_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            visible_items = [
                "• Room name (in URL path)",
                "• Message prefixes (MSG:/SYS: - 4 chars only)"
            ]
            
            for item in visible_items:
                item_padding = width - len(item) - 7
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}   {item}{' ' * item_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}{' ' * (width - 2)} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            # Encryption details
            details_title = f"{Fore.CYAN + Style.BRIGHT}🔒 ENCRYPTION DETAILS:{Style.RESET_ALL}"
            details_title_padding = width - len("🔒 ENCRYPTION DETAILS:") - 4
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {details_title}{' ' * details_title_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            details_items = [
                "• Algorithm: AES-256 in CBC mode + HMAC-SHA256",
                "• Key derivation: PBKDF2-SHA256 (100,000 iterations)",
                "• Message format: timestamp|username|content",
                "• All data encrypted before network transmission"
            ]
            
            for item in details_items:
                item_padding = width - len(item) - 7
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}   {item}{' ' * item_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
            print()
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

        elif msg == "/stats":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            uptime = ui.get_uptime()
            participants_count = len(room_participants)
            width = ui.terminal_width
            
            print(f"\n{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {Fore.WHITE + Style.BRIGHT}📊  SESSION STATISTICS{Style.RESET_ALL}{' ' * (width - 22)} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Back.BLACK}{Fore.CYAN}{'╠' + '═' * (width - 2) + '╣'}{Style.RESET_ALL}")
            
            stats = [
                ("🔒 Encryption", "AES-256-CBC + HMAC-SHA256"),
                ("🔑 Key Derivation", "PBKDF2-SHA256 (100k rounds)"),
                ("🛡️  Privacy", "Usernames, timestamps & events encrypted"),
                ("💬 Messages", f"{ui.message_count} received"),
                ("⏱️  Uptime", uptime),
                ("👥 Online", f"{participants_count} users"),
                ("🌐 Server", ntfy_server.replace('https://', ''))
            ]
            
            for label, value in stats:
                label_text = f"{Fore.YELLOW + Style.BRIGHT}{label}{Style.RESET_ALL}"
                padding = width - len(label) - len(value) - 6
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {label_text}{' ' * max(0, padding)}{value} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
            
            print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
            print()
            continue
        elif msg == "/who":
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            active_users = sorted(list(room_participants))
            width = ui.terminal_width
            
            if active_users:
                print(f"\n{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
                header_text = f"👥  ONLINE USERS ({len(active_users)})"
                header_padding = width - len(header_text) - 4
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {Fore.WHITE + Style.BRIGHT}{header_text}{Style.RESET_ALL}{' ' * header_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
                print(f"{Back.BLACK}{Fore.CYAN}{'╠' + '═' * (width - 2) + '╣'}{Style.RESET_ALL}")
                
                for user in active_users:
                    if user == nick:
                        status_icon = "👑"
                        status_text = f"{user} (you)"
                        user_color = Fore.GREEN + Style.BRIGHT
                    else:
                        status_icon = "●"
                        status_text = user
                        user_color = ui.get_user_color(user) + Style.BRIGHT
                    
                    user_padding = width - len(f"{status_icon} {status_text}") - 6
                    print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {user_color}{status_icon} {status_text}{Style.RESET_ALL}{' ' * max(0, user_padding)} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
                
                print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
            else:
                print(f"\n{Back.BLACK}{Fore.CYAN}{'╔' + '═' * (width - 2) + '╗'}{Style.RESET_ALL}")
                no_users_text = "No other participants detected yet."
                no_users_padding = width - len(no_users_text) - 4
                print(f"{Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL} {Fore.YELLOW + Style.BRIGHT}{no_users_text}{Style.RESET_ALL}{' ' * no_users_padding} {Back.BLACK}{Fore.CYAN}║{Style.RESET_ALL}")
                print(f"{Back.BLACK}{Fore.CYAN}{'╚' + '═' * (width - 2) + '╝'}{Style.RESET_ALL}")
            print()
            continue
        elif msg.strip():
            if len(msg) > MAX_MESSAGE_LENGTH:
                ui.print_system_message(f"Message too long ({len(msg)}/{MAX_MESSAGE_LENGTH} characters)", "error")
                continue
            # Clear the entire input line using ANSI escape codes
            print("\033[1A\033[2K", end="")  # Move up one line and clear it
            ui.print_user_message(nick, msg, is_own=True)
            
            # Visual feedback for message sending
            print(f"{Fore.BLUE}📤 Sending...{Style.RESET_ALL}", end="", flush=True)
            success = send_msg(room, msg, nick, fernet, ntfy_server)
            print(f"\r{' ' * 15}\r", end="")  # Clear sending message
            if success:
                print(f"{Fore.GREEN}✓ Sent{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Failed to send{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
