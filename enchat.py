#!/usr/bin/env python3
"""enchat – encrypted terminal chat (Rich UI, non-blocking sender)
Route B • 2025-06-15  CHUNK 1 / 2
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

try: import keyring; KEYRING_AVAILABLE = True        # type: ignore
except ImportError: KEYRING_AVAILABLE = False

# ── constants ─────────────────────────────────────────────────────────
CONF_FILE   = os.path.expanduser("~/.enchat.conf")
DEFAULT_NTFY= "https://ntfy.sh"
ENCHAT_NTFY = "https://enchat.sudosallie.com"
MAX_MSG_LEN = 500
PING_INTERVAL = 30
MAX_RETRIES = 3
RETRY_BASE  = 1
MAX_SEEN    = 500
BUFFER_LIMIT= 500
TRIM_STEP   = 100

console = Console()
room_participants: set[str] = set()

# ── crypto helpers ────────────────────────────────────────────────────
def gen_key(pw:str)->bytes:
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))
encrypt = lambda m,f: f.encrypt(m.encode()).decode()
def decrypt(tok,f):
    try: return f.decrypt(tok.encode()).decode()
    except InvalidToken: return ""

# ── config / keyring ──────────────────────────────────────────────────
def save_passphrase_keychain(room,secret):
    if KEYRING_AVAILABLE:
        try: keyring.set_password("enchat",f"room_{room}",secret)
        except Exception: pass
def load_passphrase_keychain(room):
    if KEYRING_AVAILABLE:
        try: return keyring.get_password("enchat",f"room_{room}") or ""
        except Exception: pass
    return ""

def save_conf(room,nick,secret,server):
    with open(CONF_FILE,"w",encoding="utf-8") as f:
        f.write(f"{room}\n{nick}\n{secret}\n{server}\n")
    try: os.chmod(CONF_FILE,0o600)
    except Exception: pass

def load_conf():
    if not os.path.exists(CONF_FILE): return None,None,None,None
    try:
        with open(CONF_FILE,encoding="utf-8") as f:
            room,nick,secret,*rest=[l.strip() for l in f.readlines()]
        server=rest[0] if rest else DEFAULT_NTFY
        if not secret: secret=load_passphrase_keychain(room)
        return room,nick,secret,server
    except Exception: return None,None,None,None

# ── notifications (silent fallback) ───────────────────────────────────
def notify(msg):
    if sys.platform.startswith("linux") and which("notify-send"):
        subprocess.run(["notify-send","Enchat",msg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    elif sys.platform=="darwin" and which("osascript"):
        subprocess.run(["osascript","-e",f'display notification "{msg}" with title "Enchat"'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    elif sys.platform=="win32":
        try: import winsound; winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception: pass

# ── global outbox (non-blocking sender) ───────────────────────────────
outbox_queue: queue.Queue = queue.Queue()

def enqueue_msg(room,nick,txt,server,f): outbox_queue.put(("MSG",room,nick,txt,server,f))
def enqueue_sys(room,nick,what,server,f): outbox_queue.put(("SYS",room,nick,what,server,f))

def outbox_worker(stop_evt:threading.Event):
    session = requests.Session()
    while not stop_evt.is_set():
        try:
            kind,room,nick,payload,server,f = outbox_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        body = (f"MSG:{encrypt(f'{int(time.time())}|{nick}|{payload}',f)}"
                if kind=="MSG"
                else f"SYS:{encrypt(f'{int(time.time())}|{nick}|SYSTEM:{payload}',f)}")
        url=f"{server}/{room}"
        retry,delay=0,2
        while retry<6 and not stop_evt.is_set():
            try:
                r=session.post(url,data=body,timeout=15)
                if r.status_code==200: break
                delay=int(r.headers.get("Retry-After",delay)) if r.status_code==429 else min(delay*2,30)
            except Exception: delay=min(delay*2,30)
            retry+=1; time.sleep(delay)
        if retry>=6 and kind=="MSG":
            console.log("[red]✗ could not deliver message after retries[/]")

# ── SSE listener ──────────────────────────────────────────────────────
def trim(buf): 
    if len(buf)>BUFFER_LIMIT: del buf[:TRIM_STEP]

def listener(room,nick,f,server,buf,stop):
    url=f"{server}/{room}/raw?x-sse=true&since=-30m&poll=65"
    headers={"Accept":"text/event-stream","Cache-Control":"no-cache"}
    seen:set[str]=set(); join_ts=int(time.time())
    room_participants.add(nick)
    with requests.Session() as sess:
        while not stop.is_set():
            try:
                with sess.get(url,stream=True,timeout=(5,None),headers=headers) as resp:
                    for raw in resp.iter_lines(decode_unicode=True,chunk_size=1):
                        if stop.is_set(): return
                        if not raw: continue
                        h=hashlib.sha256(raw.encode()).hexdigest()
                        if h in seen: continue
                        seen.add(h); seen=set(list(seen)[-MAX_SEEN:])
                        if not raw.startswith(("SYS:","MSG:")): continue
                        kind,enc=raw[:4],raw[4:]
                        plain=decrypt(enc,f); 
                        if not plain: continue
                        ts,sender,content=plain.split("|",2)
                        if kind=="SYS:":
                            evt=content.replace("SYSTEM:","")
                            if evt=="left" and sender==nick and int(ts)<join_ts: continue
                            if evt=="joined":
                                room_participants.add(sender)
                                if sender!=nick:
                                    buf.append(("System",f"{sender} joined",False))
                                    notify(f"{sender} joined")
                                    enqueue_sys(room,nick,"ping",server,f)
                            elif evt=="left":
                                room_participants.discard(sender)
                                if sender!=nick:
                                    buf.append(("System",f"{sender} left",False)); notify(f"{sender} left")
                            elif evt=="ping": room_participants.add(sender)
                        else:  # message
                            if sender!=nick:
                                room_participants.add(sender)
                                buf.append((sender,content,False)); notify(f"Msg from {sender}")
                        trim(buf)
            except Exception as e:
                console.log(f"[yellow]reconnect {e}[/]"); time.sleep(2)

# ── non-blocking char input ───────────────────────────────────────────
current_input: List[str]=[]
input_queue=queue.Queue()

def _posix():
    import termios,tty
    fd=sys.stdin.fileno(); old=termios.tcgetattr(fd); tty.setcbreak(fd)
    try:
        while True:
            if select.select([sys.stdin],[],[],0.05)[0]:
                ch=sys.stdin.read(1)
                if ch in ("\n","\r"):
                    input_queue.put("".join(current_input)); current_input.clear()
                elif ch=="\x03": input_queue.put("/exit")
                elif ch in("\x7f","\b") and current_input: current_input.pop()
                else: current_input.append(ch)
            else: time.sleep(0.05)
    finally: termios.tcsetattr(fd,termios.TCSADRAIN,old)

def _win():
    import msvcrt,time as _t
    while True:
        if msvcrt.kbhit():
            ch=msvcrt.getwch()
            if ch in ("\r","\n"):
                input_queue.put("".join(current_input)); current_input.clear()
            elif ch=="\x03": input_queue.put("/exit")
            elif ch=="\x08" and current_input: current_input.pop()
            else: current_input.append(ch)
        _t.sleep(0.05)

def start_char_thread():
    threading.Thread(target=_win if os.name=="nt" else _posix,daemon=True).start()
# ═════ UI + main (chunk 2) ═════
class ChatUI:
    def __init__(self, room,nick,server,f,buf):
        self.room,self.nick,self.server,self.f = room,nick,server,f
        self.buf=buf
        self.layout=Layout()
        self.layout.split(
            Layout(name="header",size=3),
            Layout(name="body",ratio=1),
            Layout(name="input",size=3),
        )
        self.redraw=True; self.last_len=len(buf); self.last_input=""

    # ─ render helpers ─
    def _head(self):
        return Panel(Text.assemble(
            (" ENCHAT ","bold cyan"),
            (" CONNECTED ","bold green"),
            (f" {self.room} ","white"),
            (f" {self.nick} ","magenta"),
            (" | "+self.server.replace("https://",""),"dim")),style="blue")
    def _body(self):
        t=Text()
        for u,m,own in self.buf[-100:]:
            if u=="System": t.append(f"[SYSTEM] {m}\n",style="yellow")
            else:
                lab,st=("You","green") if own else (u,"cyan")
                t.append(f"{lab}: ",style=st); t.append(f"{m}\n")
        return Panel(t,title=f"Messages ({len(self.buf)})",padding=(0,1))
    def _inp(self):
        entered="".join(current_input)
        txt=Text(f"{self.nick}: ",style="bold green")
        txt.append(entered or "…",style="white")
        txt.append(f"  {len(entered)}/{MAX_MSG_LEN}",style="dim")
        return Panel(Align.left(txt),title="Type message",padding=(0,1))

    # ─ main loop ─
    def run(self):
        stop=threading.Event()
        threading.Thread(target=listener,args=(self.room,self.nick,self.f,self.server,self.buf,stop),daemon=True).start()
        start_char_thread()

        self.buf.append(("System",f"Joined '{self.room}'",False))
        enqueue_sys(self.room,self.nick,"joined",self.server,self.f)

        def pinger():
            while not stop.is_set():
                enqueue_sys(self.room,self.nick,"ping",self.server,self.f); time.sleep(PING_INTERVAL)
        threading.Thread(target=pinger,daemon=True).start()

        with Live(self.layout,refresh_per_second=10,screen=False) as live:
            while True:
                if len(self.buf)!=self.last_len:
                    self.last_len=len(self.buf); self.redraw=True
                curr_in="".join(current_input)
                if curr_in!=self.last_input:
                    self.last_input=curr_in; self.redraw=True

                if self.redraw:
                    self.layout["header"].update(self._head())
                    self.layout["body"].update(self._body())
                    self.layout["input"].update(self._inp())
                    live.refresh(); self.redraw=False

                try: line=input_queue.get_nowait()
                except queue.Empty: time.sleep(0.05); continue

                self.redraw=True
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
                    trim(self.buf); continue
                if line=="/help":
                    for c,d in [("/help","help"),("/who","online users"),("/stats","stats"),
                                ("/security","crypto info"),("/clear","clear"),("/exit","quit")]:
                        self.buf.append(("System",f"{c}: {d}",False))
                    trim(self.buf); continue
                if line=="/stats":
                    tot=len([m for m in self.buf if m[0]!="System"])
                    mine=len([m for m in self.buf if m[0]==self.nick])
                    self.buf.append(("System",f"Sent {mine}, Recv {tot-mine}, Total {tot}",False))
                    trim(self.buf); continue
                if line=="/security":
                    self.buf.append(("System","AES-256-Fernet, PBKDF2-SHA256 (100k)",False))
                    trim(self.buf); continue
                if line.startswith("/"):
                    self.buf.append(("System",f"Unknown command {line}",False))
                    trim(self.buf); continue
                # ─ message ─
                if len(line)>MAX_MSG_LEN:
                    self.buf.append(("System","❌ too long",False)); continue
                enqueue_msg(self.room,self.nick,line,self.server,self.f)
                self.buf.append((self.nick,line,True))
                trim(self.buf)

        stop.set(); enqueue_sys(self.room,self.nick,"left",self.server,self.f)

# ═════ setup & CLI ═════
def first_run(args):
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
    else: save_conf(room,nick,secret,server)
    return room,nick,secret,server

def main():
    ap=argparse.ArgumentParser("enchat")
    ap.add_argument("--server"); ap.add_argument("--enchat-server",action="store_true")
    ap.add_argument("--default-server",action="store_true"); ap.add_argument("--reset",action="store_true")
    ns=ap.parse_args()
    if ns.reset and os.path.exists(CONF_FILE):
        os.remove(CONF_FILE); console.print("[green]settings cleared[/]"); sys.exit()

    room,nick,secret,server = load_conf()
    if not room or not nick: room,nick,secret,server=first_run(ns)
    if not secret: secret=getpass("🔑 Passphrase: ")

    f=Fernet(gen_key(secret)); buf:List[Tuple[str,str,bool]]=[]
    # global outbox worker
    out_stop=threading.Event()
    threading.Thread(target=outbox_worker,args=(out_stop,),daemon=True).start()

    ui=ChatUI(room,nick,server,f,buf)
    def quit_clean(*_):
        out_stop.set(); enqueue_sys(room,nick,"left",server,f); sys.exit()
    signal.signal(signal.SIGINT,quit_clean)

    try: ui.run()
    finally: out_stop.set(); enqueue_sys(room,nick,"left",server,f)

if __name__=="__main__":
    main()