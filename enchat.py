#!/usr/bin/env python3
"""enchat – encrypted terminal chat (Rich UI)
Route B · 2025-06-14   CHUNK 1 / 2
"""
# — stdlib —
import argparse, base64, hashlib, os, queue, select, signal, subprocess, sys, threading, time
from getpass import getpass
from shutil import which
from typing import List, Tuple
# — 3rd-party —
import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.align import Align

# optional keyring
try:
    import keyring              # type: ignore
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# ─── constants ─────────────────────────────────
CONF_FILE       = os.path.expanduser("~/.enchat.conf")
DEFAULT_NTFY    = "https://ntfy.sh"
ENCHAT_NTFY     = "https://enchat.sudosallie.com"
MAX_MSG_LEN     = 500
PING_INTERVAL   = 30
MAX_RETRIES     = 3
RETRY_BASE      = 1
MAX_SEEN        = 500
BUFFER_LIMIT    = 500
TRIM_STEP       = 100

console = Console()
room_participants: set[str] = set()

# ═════════ crypto ═════════════════════════════
def gen_key(passphrase: str) -> bytes:
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

def encrypt(msg: str, f: Fernet) -> str:
    return f.encrypt(msg.encode()).decode()

def decrypt(tok: str, f: Fernet) -> str:
    try:    return f.decrypt(tok.encode()).decode()
    except InvalidToken: return ""

# ═════════ config / keyring ═══════════════════
def save_passphrase_keychain(room: str, secret: str):
    if KEYRING_AVAILABLE:
        try: keyring.set_password("enchat", f"room_{room}", secret)
        except Exception: pass

def load_passphrase_keychain(room: str) -> str:
    if KEYRING_AVAILABLE:
        try: return keyring.get_password("enchat", f"room_{room}") or ""
        except Exception: pass
    return ""

def save_conf(room: str, nick: str, secret: str, server: str):
    with open(CONF_FILE, "w", encoding="utf-8") as fh:
        fh.write(f"{room}\n{nick}\n{secret}\n{server}\n")
    try: os.chmod(CONF_FILE, 0o600)
    except Exception: pass

def load_conf() -> Tuple[str|None,str|None,str|None,str|None]:
    if not os.path.exists(CONF_FILE):
        return None, None, None, None
    try:
        with open(CONF_FILE, encoding="utf-8") as fh:
            room, nick, secret, *rest = [l.strip() for l in fh.readlines()]
        server = rest[0] if rest else DEFAULT_NTFY
        if not secret: secret = load_passphrase_keychain(room)
        return room, nick, secret, server
    except Exception:
        return None, None, None, None

# ═════════ notifications ══════════════════════
def notify(msg: str):
    if sys.platform.startswith("linux") and which("notify-send"):
        subprocess.run(["notify-send", "Enchat", msg],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "darwin" and which("osascript"):
        subprocess.run(["osascript", "-e",
            f'display notification "{msg}" with title "Enchat"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "win32":
        try:
            import winsound      # type: ignore
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception: pass

# ═════════ HTTP helpers ═══════════════════════
def _post_with_retry(url: str, data: str) -> bool:
    retry, delay = 0, RETRY_BASE
    while retry < MAX_RETRIES:
        try:
            r = requests.post(url, data=data, timeout=10)
            if r.status_code == 200: return True
            if r.status_code == 429:
                retry += 1; delay = int(r.headers.get("Retry-After", delay))
                time.sleep(delay); delay *= 2
            else: return False
        except Exception:
            retry += 1; time.sleep(delay); delay *= 2
    return False

def send_system(room: str, nick: str, what: str,
                server: str, f: Fernet):
    ts = int(time.time())
    _post_with_retry(f"{server}/{room}",
        f"SYS:{encrypt(f'{ts}|{nick}|SYSTEM:{what}', f)}")

def send_msg(room: str, nick: str, msg: str,
             server: str, f: Fernet):
    ts = int(time.time())
    return _post_with_retry(f"{server}/{room}",
        f"MSG:{encrypt(f'{ts}|{nick}|{msg}', f)}")

# ═════════ SSE listener ═══════════════════════
def trim_buffer(buf):
    if len(buf) > BUFFER_LIMIT:
        del buf[:TRIM_STEP]

def listener(room: str, nick: str, f: Fernet, server: str,
             buf: list, stop: threading.Event):
    url = f"{server}/{room}/raw?x-sse=true&since=-30m&poll=65"
    headers = {"Accept":"text/event-stream","Cache-Control":"no-cache"}
    session = requests.Session()
    seen:set[str] = set(); join_ts=int(time.time())
    room_participants.add(nick)

    while not stop.is_set():
        try:
            with session.get(url, stream=True, timeout=(5,None),
                             headers=headers) as resp:
                for raw in resp.iter_lines(decode_unicode=True, chunk_size=1):
                    if stop.is_set(): return
                    if not raw: continue
                    h = hashlib.sha256(raw.encode()).hexdigest()
                    if h in seen: continue
                    seen.add(h); seen = set(list(seen)[-MAX_SEEN:])

                    if not raw.startswith(("SYS:","MSG:")): continue
                    kind, enc = raw[:4], raw[4:]
                    plain = decrypt(enc,f)
                    if not plain: continue
                    ts_str,sender,content = plain.split("|",2)

                    if kind=="SYS:":
                        evt = content.replace("SYSTEM:","")
                        if evt=="left" and sender==nick and int(ts_str)<join_ts:
                            continue
                        if evt=="joined":
                            room_participants.add(sender)
                            if sender!=nick:
                                buf.append(("System",f"{sender} joined",False))
                                notify(f"{sender} joined")
                                send_system(room,nick,"ping",server,f)
                        elif evt=="left":
                            room_participants.discard(sender)
                            if sender!=nick:
                                buf.append(("System",f"{sender} left",False))
                                notify(f"{sender} left")
                        elif evt=="ping":
                            room_participants.add(sender)
                    else:               # MSG
                        if sender!=nick:
                            room_participants.add(sender)
                            buf.append((sender,content,False))
                            notify(f"Message from {sender}")
                    trim_buffer(buf)
        except Exception as exc:
            console.log(f"[yellow]reconnect {exc}[/]")
            time.sleep(2)

# ═════════ non-blocking char input ════════════
current_input: List[str] = []
input_queue = queue.Queue()

def _posix_loop():
    import termios, tty
    fd = sys.stdin.fileno(); old=termios.tcgetattr(fd); tty.setcbreak(fd)
    try:
        while True:
            if select.select([sys.stdin],[],[],0.05)[0]:
                ch = sys.stdin.read(1)
                if ch in ("\n","\r"):
                    input_queue.put("".join(current_input)); current_input.clear()
                elif ch == "\x03":
                    input_queue.put("/exit")
                elif ch in ("\x7f","\b") and current_input:
                    current_input.pop()
                else:
                    current_input.append(ch)
            else:
                time.sleep(0.05)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _win_loop():
    import msvcrt, time as _t
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\r","\n"):
                input_queue.put("".join(current_input)); current_input.clear()
            elif ch == "\x03":
                input_queue.put("/exit")
            elif ch == "\x08" and current_input:
                current_input.pop()
            else:
                current_input.append(ch)
        _t.sleep(0.05)

def start_char_thread():
    threading.Thread(target=_win_loop if os.name=="nt" else _posix_loop,
                     daemon=True).start()
# ─── CHUNK-1 einde ───
# ═════════ UI + main (chunk 2) ═════════
class ChatUI:
    def __init__(self, room: str, nick: str, server: str,
                 f: Fernet, buf: list[tuple[str,str,bool]]):
        self.room, self.nick, self.server, self.f = room, nick, server, f
        self.buf = buf
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="input", size=3),
        )
        self.need_redraw = True
        self.last_len = len(self.buf)        # ← voor realtime-check

    # ── render helpers ───────────────────────
    def _head(self):
        return Panel(Text.assemble(
            (" ENCHAT ", "bold cyan"),
            (" CONNECTED ", "bold green"),
            (f" {self.room} ", "white"),
            (f" {self.nick} ", "magenta"),
            (" | "+self.server.replace("https://",""), "dim")
        ), style="blue")

    def _body(self):
        t = Text()
        for u,m,own in self.buf[-100:]:
            if u=="System":
                t.append(f"[SYSTEM] {m}\n", style="yellow")
            else:
                lbl,st = ("You","green") if own else (u,"cyan")
                t.append(f"{lbl}: ", style=st); t.append(f"{m}\n")
        return Panel(t, title=f"Messages ({len(self.buf)})", padding=(0,1))

    def _inp(self):
        txt = Text("→ ", style="bold green")
        txt.append("".join(current_input))
        txt.append(f" {len(current_input)}/{MAX_MSG_LEN}", style="dim")
        return Panel(Align.left(txt))

    # ── UI loop ──────────────────────────────
    def run(self):
        stop_evt = threading.Event()
        threading.Thread(target=listener,
                         args=(self.room,self.nick,self.f,
                               self.server,self.buf,stop_evt),
                         daemon=True).start()
        start_char_thread()

        self.buf.append(("System",f"Joined '{self.room}'",False))
        send_system(self.room,self.nick,"joined",self.server,self.f)

        def _pinger():
            while not stop_evt.is_set():
                send_system(self.room,self.nick,"ping",self.server,self.f)
                time.sleep(PING_INTERVAL)
        threading.Thread(target=_pinger, daemon=True).start()

        with Live(self.layout, refresh_per_second=10, screen=False) as live:
            while True:
                # — realtime check — (buffer groeide?)
                if len(self.buf) != self.last_len:
                    self.last_len = len(self.buf)
                    self.need_redraw = True

                if self.need_redraw:
                    self.layout["header"].update(self._head())
                    self.layout["body"].update(self._body())
                    self.layout["input"].update(self._inp())
                    live.refresh()
                    self.need_redraw = False

                try:
                    line = input_queue.get_nowait()
                except queue.Empty:
                    time.sleep(0.05); continue

                self.need_redraw = True
                if not line: continue

                # ─ commands ─
                if line=="/exit": break
                if line=="/clear": self.buf.clear(); continue
                if line=="/who":
                    room_participants.add(self.nick)
                    users=sorted(room_participants)
                    self.buf.append(("System",f"=== ONLINE ({len(users)}) ===",False))
                    for u in users:
                        tag="👑" if u==self.nick else "●"
                        self.buf.append(("System",f"{tag} {u}",False))
                    trim_buffer(self.buf); continue
                if line=="/help":
                    for c,d in [("/help","help"),("/who","online users"),
                                ("/stats","stats"),("/security","crypto info"),
                                ("/clear","clear screen"),("/exit","quit")]:
                        self.buf.append(("System",f"{c}: {d}",False))
                    trim_buffer(self.buf); continue
                if line=="/stats":
                    tot=len([m for m in self.buf if m[0]!="System"])
                    mine=len([m for m in self.buf if m[0]==self.nick])
                    self.buf.append(("System",f"Sent {mine}, Recv {tot-mine}, Total {tot}",False))
                    trim_buffer(self.buf); continue
                if line=="/security":
                    self.buf.append(("System","AES-256-Fernet, PBKDF2-SHA256 (100k)",False))
                    trim_buffer(self.buf); continue
                if line.startswith("/"):
                    self.buf.append(("System",f"Unknown command {line}",False))
                    trim_buffer(self.buf); continue

                # ─ message ─
                if len(line)>MAX_MSG_LEN:
                    self.buf.append(("System","❌ too long",False)); continue
                ok=send_msg(self.room,self.nick,line,self.server,self.f)
                self.buf.append((self.nick,line,True))
                if not ok:
                    self.buf.append(("System","❌ failed to send",False))
                trim_buffer(self.buf)

        stop_evt.set()
        send_system(self.room,self.nick,"left",self.server,self.f)

# ═════════ first-run & main ═════════
def first_run(args)->Tuple[str,str,str,str]:
    console.clear(); console.print("[bold cyan]🔐 First-time setup[/]")
    room=Prompt.ask("🏠 Room").strip().lower()
    nick=Prompt.ask("👤 Nick").strip()
    secret=getpass("🔑 Passphrase: ")
    if args.server: server=args.server.rstrip('/')
    elif args.enchat_server: server=ENCHAT_NTFY
    elif args.default_server: server=DEFAULT_NTFY
    else:
        console.print("[cyan]Server: 1) enchat  2) ntfy.sh  3) custom[/]")
        ch=Prompt.ask("Choice",choices=["1","2","3"],default="1")
        server=ENCHAT_NTFY if ch=="1" else DEFAULT_NTFY if ch=="2" else Prompt.ask("URL").rstrip('/')
    save_conf(room,nick,"",server)
    if KEYRING_AVAILABLE and Prompt.ask("Save passphrase in keychain?",choices=["y","n"],default="y")=="y":
        save_passphrase_keychain(room,secret)
    else:
        save_conf(room,nick,secret,server)
    return room,nick,secret,server

def main():
    ap=argparse.ArgumentParser("enchat")
    ap.add_argument("--server");ap.add_argument("--enchat-server",action="store_true")
    ap.add_argument("--default-server",action="store_true");ap.add_argument("--reset",action="store_true")
    ns=ap.parse_args()

    if ns.reset and os.path.exists(CONF_FILE):
        os.remove(CONF_FILE); console.print("[green]settings cleared[/]"); sys.exit()

    room,nick,secret,server=load_conf()
    if not room or not nick:
        room,nick,secret,server=first_run(ns)
    if not secret:
        secret=getpass("🔑 Passphrase: ")

    f=Fernet(gen_key(secret))
    buf: List[Tuple[str,str,bool]]=[]
    ui=ChatUI(room,nick,server,f,buf)

    def bye(*_):
        send_system(room,nick,"left",server,f); console.print("[yellow]bye[/]"); sys.exit()
    signal.signal(signal.SIGINT,bye)

    ui.run()

if __name__=="__main__":
    main()