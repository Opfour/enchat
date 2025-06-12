#!/usr/bin/env python3
"""enchat – encrypted terminal chat
fixed UI + full original functionality (2025‑06‑13)"""
# ———————————————————————————————————————————————————
import os, sys, time, signal, threading, queue, argparse, base64, hashlib, select, subprocess, requests
from getpass import getpass
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

# optional keyring
try:
    import keyring  # type: ignore
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# — configuration —
CONF_FILE      = os.path.expanduser("~/.enchat.conf")
DEFAULT_NTFY   = "https://ntfy.sh"
ENCHAT_NTFY    = "https://enchat.sudosallie.com"
MAX_MSG_LEN    = 500
PING_INTERVAL  = 30
MAX_RETRIES    = 3
RETRY_BASE     = 1
CONN_TIMEOUT   = 70
MAX_SEEN       = 500

console = Console()
room_participants: set[str] = set()
last_ping_time = 0.0

# — crypto helpers —

def gen_key(secret: str) -> bytes:
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))

encrypt = lambda m, f: f.encrypt(m.encode()).decode()

def decrypt(t: str, f: Fernet) -> str:
    try:
        return f.decrypt(t.encode()).decode()
    except InvalidToken:
        return ""

# — config helpers —

def save_passphrase_keychain(room: str, secret: str) -> bool:
    if not KEYRING_AVAILABLE: return False
    try: keyring.set_password("enchat", f"room_{room}", secret); return True
    except Exception: return False

def load_passphrase_keychain(room: str) -> str:
    if not KEYRING_AVAILABLE: return ""
    try: return keyring.get_password("enchat", f"room_{room}") or ""
    except Exception: return ""

def save_conf(room: str, nick: str, secret: str, server: str):
    with open(CONF_FILE, "w") as fp:
        fp.write(f"{room}\n{nick}\n{secret}\n{server}\n")
    try: os.chmod(CONF_FILE, 0o600)
    except Exception: pass

def load_conf() -> Tuple[str|None,str|None,str|None,str|None]:
    if not os.path.exists(CONF_FILE):
        return None, None, None, None
    try:
        with open(CONF_FILE) as fp:
            room, nick, secret, *rest = [l.strip() for l in fp.readlines()]
        server = rest[0] if rest else DEFAULT_NTFY
        if not secret and room:
            secret = load_passphrase_keychain(room)
        return room, nick, secret, server
    except Exception:
        return None, None, None, None

# — notifications —

def notify(msg: str):
    if sys.platform.startswith("linux") and which("notify-send"):
        subprocess.run(["notify-send", "Enchat", msg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "darwin" and which("osascript"):
        subprocess.run(["osascript", "-e", f'display notification "{msg}" with title "Enchat"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "win32":
        try:
            import winsound; winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception: pass

# — ntfy POST helper —

def _post_with_retry(url: str, data: str) -> bool:
    retry, delay = 0, RETRY_BASE
    while retry < MAX_RETRIES:
        try:
            r = requests.post(url, data=data, timeout=10)
            if r.status_code == 200: return True
            if r.status_code == 429:
                retry += 1; delay = int(r.headers.get("Retry-After", delay)); time.sleep(delay); delay *= 2
            else: return False
        except Exception:
            retry += 1; time.sleep(delay); delay *= 2
    return False

def send_system(room: str, nick: str, what: str, server: str, f: Fernet):
    ts = int(time.time()); _post_with_retry(f"{server}/{room}", f"SYS:{encrypt(f'{ts}|{nick}|SYSTEM:{what}', f)}")

def send_msg(room: str, nick: str, msg: str, server: str, f: Fernet) -> bool:
    ts = int(time.time()); return _post_with_retry(f"{server}/{room}", f"MSG:{encrypt(f'{ts}|{nick}|{msg}', f)}")

# — listener —
# Keep track of when *this* client joined so we can ignore stale "left"
join_ts = int(time.time())

def listen(room: str, nick: str, f: Fernet, server: str, msgs: list, stop: threading.Event):
    global last_ping_time
    url = f"{server}/{room}/raw?x-sse=true&since=-30m&poll=65"
    headers = {"Accept":"text/event-stream", "Cache-Control":"no-cache"}
    seen: set[str] = set(); session = requests.Session(); room_participants.add(nick)
    while not stop.is_set():
        try:
            with session.get(url, stream=True, timeout=CONN_TIMEOUT, headers=headers) as resp:
                for raw in resp.iter_lines(decode_unicode=True):
                    if stop.is_set(): return
                    if not raw: continue
                    h = hashlib.sha256(raw.encode()).hexdigest();
                    if h in seen: continue; seen.add(h)
                    if len(seen) > MAX_SEEN: seen = set(list(seen)[-MAX_SEEN//2:])
                    if raw.startswith(("SYS:", "MSG:")):
                        kind, enc = raw[:4], raw[4:]
                        plain = decrypt(enc, f)
                        if not plain: continue
                        _, sender, content = plain.split("|", 2)
                        if kind == "SYS:":
                            evt = content.replace("SYSTEM:", "")
                            # ignore stale "left" events that happened before we joined
                            if evt == "left" and sender == nick:
                                try:
                                    if int(ts) < join_ts:
                                        continue  # skip old leave of ourselves
                                except Exception:
                                    continue
                            if evt == "joined":
                                room_participants.add(sender)
                                if sender != nick:
                                    msgs.append(("System", f"{sender} joined", False)); notify(f"{sender} joined"); send_system(room, nick, "ping", server, f)
                            if len(msgs) > 500:
                                del msgs[:100]
                            elif evt == "left":
                                room_participants.discard(sender)
                                if sender != nick:
                                    msgs.append(("System", f"{sender} left", False)); notify(f"{sender} left")
                            if len(msgs) > 500:
                                del msgs[:100]
                            elif evt == "ping":
                                room_participants.add(sender)
                        else:
                            if sender != nick: room_participants.add(sender); msgs.append((sender, content, False)); notify(f"Message from {sender}")
                            if len(msgs) > 500:
                                del msgs[:100]
        except Exception as exc:
            console.log(f"[red]conn error:[/] {exc}"); time.sleep(2)

# — non‑blocking char input —
current_input: list[str] = []
input_queue = queue.Queue()

def _posix_loop():
    import termios, tty
    fd = sys.stdin.fileno(); old = termios.tcgetattr(fd); tty.setcbreak(fd)
    try:
        while True:
            if select.select([sys.stdin], [], [], 0.05)[0]:
                ch = sys.stdin.read(1)
                if ch in ("\n", "\r"):
                    line = "".join(current_input); current_input.clear(); input_queue.put(line)
                elif ch == "\x03": input_queue.put("/exit")
                elif ch in ("\x7f", "\b") and current_input: current_input.pop()
                else: current_input.append(ch)
            else: time.sleep(0.05)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _win_loop():
    import msvcrt
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                line = "".join(current_input); current_input.clear(); input_queue.put(line)
            elif ch == "\x03": input_queue.put("/exit")
            elif ch == "\x08" and current_input: current_input.pop()
            else: current_input.append(ch)
        time.sleep(0.05)

def start_char_thread():
    threading.Thread(target=_win_loop if os.name=='nt' else _posix_loop, daemon=True).start()

# — UI —
class ChatUI:
    def __init__(self, room: str, nick: str, server: str, f: Fernet, msgs: list):
        self.room, self.nick, self.server, self.f = room, nick, server, f
        self.msgs = msgs
        self.layout = Layout(); self.layout.split(Layout(name="header", size=3), Layout(name="body", ratio=1), Layout(name="input", size=3))

    def _header(self):
        t = Text.assemble((" ENCHAT ", "bold cyan"),(" CONNECTED ", "bold green"),(f" Room: {self.room} ", "white"),(f" Nick: {self.nick} ", "magenta"))
        return Panel(t, style="blue")
    def _body(self):
        txt = Text()
        for u,m,own in self.msgs[-200:]:
            if u=="System": txt.append(f"[SYSTEM] {m}\n", style="yellow")
            else:
                lbl, st = ("You","green") if own else (u,"cyan"); txt.append(f"{lbl}: ", style=st); txt.append(f"{m}\n")
        return Panel(txt, title="Messages")
    def _input(self):
        return Panel(f"{self.nick}: " + "".join(current_input), title="Type & ↵")

    def run(self):
        stop = threading.Event(); threading.Thread(target=listen, args=(self.room,self.nick,self.f,self.server,self.msgs,stop),daemon=True).start()
        start_char_thread()
        self.msgs.append(("System", f"Joined {self.room}", False)); send_system(self.room,self.nick,"joined",self.server,self.f)
        if len(self.msgs) > 500:
            del self.msgs[:100]
        with Live(self.layout, refresh_per_second=5, screen=False) as live:
            while True:
                self.layout["header"].update(self._header()); self.layout["body"].update(self._body()); self.layout["input"].update(self._input()); live.refresh()
                try: line = input_queue.get_nowait()
                except queue.Empty: time.sleep(0.05); continue
                if not line: continue
                if line in ("/exit","/quit"): break
                self._handle(line)
        stop.set(); send_system(self.room,self.nick,"left",self.server,self.f)

    def _handle(self, line: str):
        if len(line) > MAX_MSG_LEN:
            self.msgs.append(("System", "❌ message too long", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if not line.startswith("/"):
            ok = send_msg(self.room,self.nick,line,self.server,self.f); self.msgs.append((self.nick,line,True))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            if not ok: self.msgs.append(("System","❌ failed",False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        cmd = line.lower().strip()
        if cmd == "/clear": self.msgs.clear(); return
        if cmd == "/help":
            for c,d in [("/help","help"),("/clear","clear screen"),("/exit","leave"),("/who","participants"),("/stats","stats"),("/security","crypto info"),("/server","server info")]:
                self.msgs.append(("System", f"{c}: {d}", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if cmd == "/who":
            # make sure we always report ourselves even if an old "left" event pruned us
            room_participants.add(self.nick)
            users = sorted(room_participants)
            self.msgs.append(("System", f"=== ONLINE ({len(users)}) ===", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            for u in users: 
                tag = "👑" if u==self.nick else "●"
                self.msgs.append(("System", f"{tag} {u}", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if cmd == "/stats":
            tot = len([m for m in self.msgs if m[0]!="System"])
            mine = len([m for m in self.msgs if m[0]==self.nick])
            self.msgs.append(("System", f"Sent {mine} / Recv {tot-mine} / Total {tot}", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if cmd == "/security": 
            self.msgs.append(("System","AES‑256 (Fernet), PBKDF2‑SHA256 100k",False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if cmd == "/server": 
            self.msgs.append(("System", f"Server {self.server}", False))
            if len(self.msgs) > 500:
                del self.msgs[:100]
            return
        if not line.startswith("/"): return
        self.msgs.append(("System", f"Unknown command {cmd}", False))
        if len(self.msgs) > 500:
            del self.msgs[:100]

# — setup helpers —

def first_run(args) -> Tuple[str, str, str, str]:
    """Interactive first‑time setup, including server choice."""
    console.clear(); console.print("[bold cyan]🔐 First‑time setup[/]")
    room = Prompt.ask("🏠 Room name").strip().lower()
    nick = Prompt.ask("👤 Nickname").strip()
    secret = getpass("🔑 Passphrase: ")

    # ─── Choose ntfy server ───
    if args.server:
        server = args.server.rstrip('/')
    elif args.enchat_server:
        server = ENCHAT_NTFY
    elif args.default_server:
        server = DEFAULT_NTFY
    else:
        console.print("[cyan]🌐 Select ntfy server:[/]")
        console.print(f"  [yellow]1)[/] Enchat dedicated server ({ENCHAT_NTFY}) – recommended")
        console.print(f"  [yellow]2)[/] Default public server ({DEFAULT_NTFY}) – rate‑limited")
        console.print("  [yellow]3)[/] Custom server URL")
        choice = Prompt.ask("Option", choices=["1","2","3"], default="1")
        if choice == "1":
            server = ENCHAT_NTFY
        elif choice == "2":
            server = DEFAULT_NTFY
        else:
            server = Prompt.ask("Enter full server URL (e.g. https://ntfy.example.org)").rstrip('/')

    # save minimal config (no secret yet)
    save_conf(room, nick, "", server)
    if KEYRING_AVAILABLE and Prompt.ask("Save passphrase in keychain?", choices=["y","n"], default="y") == "y":
        save_passphrase_keychain(room, secret)
    else:
        save_conf(room, nick, secret, server)
    return room, nick, secret, server

# — main —
if __name__ == "__main__":
    ap = argparse.ArgumentParser("enchat")
    ap.add_argument("--server", help="use custom ntfy server (https://…)")
    ap.add_argument("--enchat-server", action="store_true", help="use enchat.sudosallie.com")
    ap.add_argument("--default-server", action="store_true", help="use default ntfy.sh")
    ap.add_argument("--reset", action="store_true", help="clear saved settings")
    ns = ap.parse_args()
    if ns.reset and os.path.exists(CONF_FILE): os.remove(CONF_FILE); console.print("[green]settings cleared[/]"); sys.exit()
    room,nick,secret,server = load_conf()
    if not room or not nick: room,nick,secret,server = first_run(ns)
    if not secret: secret = getpass("🔑 Passphrase: ")
    key, f = gen_key(secret), Fernet(gen_key(secret))
    msgs: List[Tuple[str,str,bool]] = []
    ui = ChatUI(room,nick,server,f,msgs)
    def bye(*_): sys.exit()
    signal.signal(signal.SIGINT, bye)
    stop = threading.Event()
    def pinger():
        while not stop.is_set(): send_system(room,nick,"ping",server,f); time.sleep(PING_INTERVAL)
    threading.Thread(target=pinger, daemon=True).start()
    try: ui.run()
    finally: stop.set(); send_system(room,nick,"left",server,f); console.print("[green]bye![/]")
