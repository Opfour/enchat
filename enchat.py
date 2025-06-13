#!/usr/bin/env python3
"""enchat – encrypted terminal chat (Rich UI, non-blocking sender)
Route B • 2025-06-15  CHUNK 1 / 2
"""
# — stdlib —
import argparse, base64, hashlib, os, queue, select, signal, subprocess, sys, threading, time, tempfile
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

# File transfer constants
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
CHUNK_SIZE = 6 * 1024  # 6KB chunks (safe for ntfy)
FILE_TEMP_DIR = os.path.join(tempfile.gettempdir(), "enchat_files")
DOWNLOADS_DIR = os.path.join(os.path.dirname(__file__), "downloads")

console = Console()
room_participants: set[str] = set()
notifications_enabled = True  # Global notifications toggle

# File transfer state
available_files: dict[str, dict] = {}
file_chunks: dict[str, dict] = {}  # Store chunks during transfer

# ── crypto helpers ────────────────────────────────────────────────────
def gen_key(pw:str)->bytes:
    salt = hashlib.sha256(b"enchat_v3_static_salt").digest()[:16]
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))
encrypt = lambda m,f: f.encrypt(m.encode()).decode()
def decrypt(tok,f):
    try: return f.decrypt(tok.encode()).decode()
    except InvalidToken: return ""

# ── file transfer helpers ─────────────────────────────────────────────
def ensure_file_dir():
    """Ensure secure temporary directory exists"""
    os.makedirs(FILE_TEMP_DIR, mode=0o700, exist_ok=True)

def ensure_downloads_dir():
    """Ensure downloads directory exists in project folder"""
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)

def sanitize_filename(filename, fallback_id="unknown"):
    """
    Sanitize filename to prevent directory traversal and other security issues.
    Returns a safe filename suitable for use in downloads directory.
    """
    if not filename:
        return f"file_{fallback_id}"
    
    # Remove any path components (prevents ../../../etc/passwd attacks)
    safe_name = os.path.basename(filename)
    
    # Handle special cases
    if not safe_name or safe_name in ('.', '..') or safe_name.startswith('.'):
        return f"file_{fallback_id}"
    
    # Remove dangerous characters for cross-platform compatibility
    import re
    safe_name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', safe_name)
    
    # Ensure reasonable length (255 chars is filesystem limit on most systems)
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:255-len(ext)] + ext
    
    return safe_name if safe_name else f"file_{fallback_id}"

def split_file_to_chunks(filepath, f_cipher):
    """Split file into encrypted chunks for transfer"""
    if not os.path.exists(filepath):
        return None, "File not found"
    
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        return None, f"File too large (max {MAX_FILE_SIZE // (1024*1024)}MB)"
    
    import uuid
    file_id = str(uuid.uuid4())[:8]
    filename = os.path.basename(filepath)
    file_hash = hashlib.sha256()
    chunks = []
    
    try:
        with open(filepath, 'rb') as f:
            chunk_num = 0
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break
                
                file_hash.update(chunk_data)
                # Encrypt the chunk
                encrypted_chunk = f_cipher.encrypt(chunk_data).decode()
                chunks.append({
                    'file_id': file_id,
                    'chunk_num': chunk_num,
                    'data': encrypted_chunk
                })
                chunk_num += 1
        
        metadata = {
            'file_id': file_id,
            'filename': filename,
            'size': file_size,
            'total_chunks': len(chunks),
            'hash': file_hash.hexdigest()
        }
        
        return metadata, chunks
    except Exception as e:
        return None, f"Error reading file: {e}"

def handle_file_metadata(metadata, sender, buf):
    """Handle incoming file metadata"""
    file_id = metadata['file_id']
    filename = metadata['filename']
    size = metadata['size']
    total_chunks = metadata['total_chunks']
    
    available_files[file_id] = {
        'metadata': metadata,
        'sender': sender,
        'chunks_received': 0,
        'total_chunks': total_chunks,
        'complete': False
    }
    file_chunks[file_id] = {}
    
    size_mb = size / (1024 * 1024)
    buf.append(("System", f"📎 {sender} shared: {filename} ({size_mb:.1f}MB, {total_chunks} chunks)", False))
    buf.append(("System", f"   File ID: {file_id} - Use '/download {file_id}' when complete", False))
    
    if notifications_enabled:
        notify(f"{sender} shared file: {filename}")

def handle_file_chunk(chunk_data, sender, buf):
    """Handle incoming file chunk"""
    file_id = chunk_data['file_id']
    chunk_num = chunk_data['chunk_num']
    
    if file_id in available_files:
        # Store the chunk
        file_chunks[file_id][chunk_num] = chunk_data
        available_files[file_id]['chunks_received'] = len(file_chunks[file_id])
        
        received = available_files[file_id]['chunks_received']
        total = available_files[file_id]['total_chunks']
        filename = available_files[file_id]['metadata']['filename']
        
        # Show progress every 10% or when complete
        if received % max(1, total // 10) == 0 or received == total:
            progress = int((received / total) * 100)
            buf.append(("System", f"📥 {filename}: {progress}% ({received}/{total})", False))
        
        # Mark as complete when all chunks received
        if received == total:
            available_files[file_id]['complete'] = True
            buf.append(("System", f"✅ {filename} ready! Use '/download {file_id}'", False))

def assemble_file_from_chunks(file_id, f_cipher):
    """Assemble file from chunks and save to temp directory"""
    if file_id not in available_files or not available_files[file_id]['complete']:
        return None, "File not available or incomplete"
    
    ensure_file_dir()
    metadata = available_files[file_id]['metadata']
    chunks_dict = file_chunks[file_id]
    
    try:
        # Sort chunks by number
        sorted_chunks = [chunks_dict[i] for i in sorted(chunks_dict.keys())]
        
        temp_path = os.path.join(FILE_TEMP_DIR, f"{file_id}_{metadata['filename']}")
        file_hash = hashlib.sha256()
        
        with open(temp_path, 'wb') as f:
            for chunk in sorted_chunks:
                # Decrypt chunk
                decrypted_data = f_cipher.decrypt(chunk['data'].encode())
                file_hash.update(decrypted_data)
                f.write(decrypted_data)
        
        # Verify file integrity
        if file_hash.hexdigest() != metadata['hash']:
            os.remove(temp_path)
            return None, "File integrity check failed"
        
        return temp_path, None
    except Exception as e:
        return None, f"Error assembling file: {e}"

def enqueue_file_chunk(room, nick, chunk_data, server, f):
    """Send a file chunk"""
    import json
    chunk_json = json.dumps(chunk_data)
    outbox_queue.put(("FILECHUNK", room, nick, chunk_json, server, f))

def enqueue_file_meta(room, nick, metadata, server, f):
    """Send file metadata"""
    import json
    meta_json = json.dumps(metadata)
    outbox_queue.put(("FILEMETA", room, nick, meta_json, server, f))

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
    if not notifications_enabled:
        return
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
        
        if kind=="MSG":
            body = f"MSG:{encrypt(f'{int(time.time())}|{nick}|{payload}',f)}"
        elif kind=="SYS":
            body = f"SYS:{encrypt(f'{int(time.time())}|{nick}|SYSTEM:{payload}',f)}"
        elif kind=="FILEMETA":
            body = f"FILEMETA:{encrypt(f'{int(time.time())}|{nick}|{payload}',f)}"
        elif kind=="FILECHUNK":
            body = f"FILECHUNK:{encrypt(f'{int(time.time())}|{nick}|{payload}',f)}"
        else:
            continue
            
        url=f"{server}/{room}"
        retry,delay=0,2
        while retry<6 and not stop_evt.is_set():
            try:
                r=session.post(url,data=body,timeout=15)
                if r.status_code==200: break
                delay=int(r.headers.get("Retry-After",delay)) if r.status_code==429 else min(delay*2,30)
            except Exception: delay=min(delay*2,30)
            retry+=1; time.sleep(delay)
        if retry>=6 and kind in ["MSG", "FILEMETA", "FILECHUNK"]:
            console.log(f"[red]✗ could not deliver {kind.lower()} after retries[/]")

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
                        if not raw.startswith(("SYS:","MSG:","FILEMETA:","FILECHUNK:")): continue
                        
                        if raw.startswith("FILEMETA:"):
                            kind,enc="FILEMETA:",raw[9:]
                        elif raw.startswith("FILECHUNK:"):
                            kind,enc="FILECHUNK:",raw[10:]
                        else:
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
                        elif kind=="FILEMETA:":
                            if sender!=nick:
                                import json
                                try:
                                    metadata = json.loads(content)
                                    handle_file_metadata(metadata, sender, buf)
                                except json.JSONDecodeError:
                                    pass
                        elif kind=="FILECHUNK:":
                            if sender!=nick:
                                import json
                                try:
                                    chunk_data = json.loads(content)
                                    handle_file_chunk(chunk_data, sender, buf)
                                except json.JSONDecodeError:
                                    pass
                        else:  # MSG
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
                                ("/security","crypto info"),("/server","server info"),("/notifications","toggle notifications"),
                                ("/share <file>","share file (encrypted transfer)"),("/files","list available files"),("/download <id>","download file"),
                                ("/clear","clear"),("/exit","quit")]:
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
                if line=="/server":
                    try:
                        # Test server connectivity
                        test_resp = requests.get(f"{self.server}/v1/health", timeout=5)
                        status = "🟢 Online" if test_resp.status_code == 200 else f"🟡 Status {test_resp.status_code}"
                    except Exception:
                        status = "🔴 Offline/Unreachable"
                    
                    self.buf.append(("System", f"=== SERVER INFO ===", False))
                    self.buf.append(("System", f"URL: {self.server}", False))
                    self.buf.append(("System", f"Status: {status}", False))
                    self.buf.append(("System", f"Room: {self.room}", False))
                    trim(self.buf); continue
                if line=="/notifications":
                    global notifications_enabled
                    notifications_enabled = not notifications_enabled
                    status = "enabled" if notifications_enabled else "disabled"
                    self.buf.append(("System", f"📱 Notifications {status}", False))
                    trim(self.buf); continue
                if line=="/files":
                    if not available_files:
                        self.buf.append(("System", "📂 No files available for download", False))
                    else:
                        self.buf.append(("System", f"📂 AVAILABLE FILES ({len(available_files)})", False))
                        for file_id, info in available_files.items():
                            meta = info['metadata']
                            sender = info['sender']
                            status = "✅ Ready" if info['complete'] else f"📥 {info['chunks_received']}/{info['total_chunks']}"
                            size_mb = meta['size'] / (1024 * 1024)
                            # SECURITY: Sanitize filename for display to prevent terminal injection
                            display_name = sanitize_filename(meta['filename'], file_id)
                            self.buf.append(("System", f"  {file_id}: {display_name} ({size_mb:.1f}MB) from {sender} - {status}", False))
                    trim(self.buf); continue
                if line.startswith("/download "):
                    file_id = line[10:].strip()
                    if not file_id:
                        self.buf.append(("System", "❌ Usage: /download <file_id>", False))
                        trim(self.buf); continue
                    
                    if file_id not in available_files:
                        self.buf.append(("System", f"❌ File ID '{file_id}' not found. Use /files to list available files.", False))
                        trim(self.buf); continue
                    
                    file_info = available_files[file_id]
                    if not file_info['complete']:
                        self.buf.append(("System", f"❌ File '{file_id}' is not complete yet ({file_info['chunks_received']}/{file_info['total_chunks']} chunks)", False))
                        trim(self.buf); continue
                    
                    # Assemble and save file
                    temp_path, error = assemble_file_from_chunks(file_id, self.f)
                    if error:
                        self.buf.append(("System", f"❌ Download failed: {error}", False))
                        trim(self.buf); continue
                    
                    # Ensure downloads directory exists
                    ensure_downloads_dir()
                    
                    # SECURITY: Sanitize filename to prevent directory traversal attacks
                    raw_filename = file_info['metadata']['filename']
                    filename = sanitize_filename(raw_filename, file_id)
                    
                    local_path = os.path.join(DOWNLOADS_DIR, filename)
                    
                    # SECURITY: Verify the resolved path is actually within downloads directory
                    abs_downloads = os.path.abspath(DOWNLOADS_DIR)
                    abs_local = os.path.abspath(local_path)
                    if not abs_local.startswith(abs_downloads + os.sep) and abs_local != abs_downloads:
                        self.buf.append(("System", f"❌ Security error: Invalid file path", False))
                        trim(self.buf); continue
                    
                    # Handle file exists
                    counter = 1
                    original_path = local_path
                    while os.path.exists(local_path):
                        name, ext = os.path.splitext(filename)
                        candidate_name = f"{name}_{counter}{ext}"
                        local_path = os.path.join(DOWNLOADS_DIR, candidate_name)
                        
                        # SECURITY: Verify each candidate path is also safe
                        abs_candidate = os.path.abspath(local_path)
                        if not abs_candidate.startswith(abs_downloads + os.sep) and abs_candidate != abs_downloads:
                            self.buf.append(("System", f"❌ Security error: Cannot create safe filename", False))
                            trim(self.buf); continue
                        counter += 1
                    
                    try:
                        import shutil
                        shutil.copy2(temp_path, local_path)
                        # Clean up temp file
                        os.remove(temp_path)
                        
                        size_mb = file_info['metadata']['size'] / (1024 * 1024)
                        rel_path = os.path.relpath(local_path, os.path.dirname(__file__))
                        self.buf.append(("System", f"✅ Downloaded: {os.path.basename(local_path)} ({size_mb:.1f}MB)", False))
                        self.buf.append(("System", f"   📁 Saved to: {rel_path}", False))
                        
                        # Remove from available files after download
                        del available_files[file_id]
                        del file_chunks[file_id]
                        
                    except Exception as e:
                        self.buf.append(("System", f"❌ Save failed: {e}", False))
                        # Clean up temp file on error
                        try:
                            os.remove(temp_path)
                        except:
                            pass
                    
                    trim(self.buf); continue
                if line.startswith("/share "):
                    filepath = line[7:].strip()
                    if not filepath:
                        self.buf.append(("System", "❌ Usage: /share <filepath>", False))
                        trim(self.buf); continue
                    
                    # Expand home directory
                    filepath = os.path.expanduser(filepath)
                    self.buf.append(("System", f"🔍 Preparing to share: {filepath}", False))
                    
                    # Split file into chunks and send
                    metadata, chunks = split_file_to_chunks(filepath, self.f)
                    if not metadata:
                        self.buf.append(("System", f"❌ {chunks}", False))  # chunks contains error message
                        trim(self.buf); continue
                    
                    filename = metadata['filename']
                    file_size = metadata['size']
                    total_chunks = metadata['total_chunks']
                    file_id = metadata['file_id']
                    
                    # First send metadata
                    enqueue_file_meta(self.room, self.nick, metadata, self.server, self.f)
                    
                    # Also add to own available files for testing/reference
                    available_files[file_id] = {
                        'metadata': metadata,
                        'sender': f"{self.nick} (you)",
                        'chunks_received': total_chunks,
                        'total_chunks': total_chunks,
                        'complete': True
                    }
                    file_chunks[file_id] = {i: chunks[i] for i in range(total_chunks)}
                    
                    size_mb = file_size / (1024 * 1024)
                    self.buf.append(("System", f"📤 Sharing: {filename} ({size_mb:.1f}MB, {total_chunks} chunks)", False))
                    self.buf.append(("System", f"   File ID: {file_id} (also in your /files for reference)", False))
                    
                    # Send chunks with progress
                    for i, chunk in enumerate(chunks):
                        enqueue_file_chunk(self.room, self.nick, chunk, self.server, self.f)
                        # Show progress every 10% or for small files every chunk
                        if total_chunks <= 10 or (i + 1) % max(1, total_chunks // 10) == 0 or (i + 1) == total_chunks:
                            progress = int(((i + 1) / total_chunks) * 100)
                            self.buf.append(("System", f"📤 Upload progress: {progress}% ({i + 1}/{total_chunks})", False))
                    
                    self.buf.append(("System", f"✅ Upload complete: {filename}", False))
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