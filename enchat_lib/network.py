import threading
import time
import queue
import requests
import hashlib
import json
import sys
from rich.console import Console

from . import state, constants, crypto, notifications, session_key, file_transfer
from .utils import trim

console = Console()
session = requests.Session()

def configure_tor():
    """Configures the application to use Tor SOCKS proxy."""
    console.print("[bold purple]🧅 Attempting to connect via Tor...[/]")
    
    try:
        import socks
    except ImportError:
        console.print("[bold red]❌ Tor Connection Failed.[/]")
        console.print("   [dim]Error: Missing dependencies for SOCKS support.[/]")
        console.print("   [yellow]Please run the installer again to fix this:[/]")
        console.print("   [bold cyan]./uninstall.sh && ./install.sh[/]")
        sys.exit(1)
        
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    try:
        # Use the official Tor Project check API. It's more reliable.
        # We increase the timeout to give Tor more time to bootstrap if needed.
        resp = session.get("https://check.torproject.org/api/ip", timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("IsTor"):
            raise requests.exceptions.RequestException("Tor check API reports this is not a Tor exit node.")
        state.tor_ip = data.get("IP")
        console.print("[bold green]✅ Successfully connected to Tor.[/]")
    except requests.exceptions.RequestException as e:
        console.print("[bold red]❌ Tor Connection Failed.[/]")
        # The error from requests can be verbose. We simplify it.
        if "SOCKS" in str(e):
             console.print("   [dim]Error: Missing dependencies for SOCKS support.[/]")
             console.print("   [yellow]Please ensure Tor is running and accessible on SOCKS port 9050.[/]")
        else:
             console.print(f"   [dim]Error: {e}[/]")
             console.print("   [yellow]Please ensure Tor is running and accessible on SOCKS port 9050.[/]")
        sys.exit(1)

def enqueue_msg(room, nick, txt, server, f):
    state.outbox_queue.put(("MSG", room, nick, txt, server, f))

def enqueue_sys(room, nick, what, server, f):
    state.outbox_queue.put(("SYS", room, nick, what, server, f))

def outbox_worker(stop_evt: threading.Event):
    """Worker thread for sending messages from the outbox queue."""
    while not stop_evt.is_set():
        try:
            item = state.outbox_queue.get(timeout=0.5)
            kind, room, nick, payload, server, f = item
        except queue.Empty:
            continue
        
        try:
            if session_key.should_rotate_key(room):
                new_key = session_key.generate_session_key()
                session_key.set_session_key(room, new_key)
                encrypted_key = session_key.encrypt_session_key(new_key, f)
                body = f"SESSIONKEY:{encrypted_key}"
                try:
                    session.post(f"{server}/{room}", data=body, timeout=15)
                except Exception:
                    pass

            current_key = session_key.get_session_key(room)
            if not current_key:
                current_key = session_key.generate_session_key()
                session_key.set_session_key(room, current_key)
                encrypted_key = session_key.encrypt_session_key(current_key, f)
                body = f"SESSIONKEY:{encrypted_key}"
                try:
                    session.post(f"{server}/{room}", data=body, timeout=15)
                except Exception:
                    pass

            if kind in ["MSG", "SYS", "FILEMETA", "FILECHUNK"]:
                ts = int(time.time())
                content = f"SYSTEM:{payload}" if kind == "SYS" else payload
                msg_to_encrypt = f'{ts}|{nick}|{content}'
                session_encrypted = session_key.encrypt_with_session(msg_to_encrypt, current_key)
                body = f"{kind}:{crypto.encrypt(session_encrypted, f)}"
            else:
                continue
            
            url = f"{server}/{room}"
            retry, delay = 0, 2
            while retry < 6 and not stop_evt.is_set():
                try:
                    r = session.post(url, data=body, timeout=15)
                    if r.status_code == 200:
                        break
                    delay = int(r.headers.get("Retry-After", delay)) if r.status_code == 429 else min(delay * 2, 30)
                except Exception:
                    delay = min(delay * 2, 30)
                retry += 1
                time.sleep(delay)

            if retry >= 6:
                console.log(f"[red]✗ could not deliver {kind.lower()} after retries[/]")
        finally:
            state.outbox_queue.task_done()

def listener(room, nick, f, server, buf, stop_evt: threading.Event):
    """Worker thread for listening to SSE events."""
    url = f"{server}/{room}/raw?x-sse=true&since=-30m&poll=65"
    headers = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
    seen: set[str] = set()
    join_ts = int(time.time())
    state.room_participants.add(nick)
    
    while not stop_evt.is_set():
        try:
            with session.get(url, stream=True, timeout=(5, None), headers=headers) as resp:
                for raw in resp.iter_lines(decode_unicode=True, chunk_size=1):
                    if stop_evt.is_set(): return
                    if not raw: continue

                    h = hashlib.sha256(raw.encode()).hexdigest()
                    if h in seen: continue
                    seen.add(h)
                    if len(seen) > constants.MAX_SEEN:
                        seen = set(list(seen)[-constants.MAX_SEEN:])
                    
                    raw_type, _, raw_content = raw.partition(':')

                    if raw_type == "SESSIONKEY":
                        new_key = session_key.decrypt_session_key(raw_content, f)
                        if new_key:
                            session_key.set_session_key(room, new_key)
                        continue
                    
                    if raw_type not in ["SYS", "MSG", "FILEMETA", "FILECHUNK"]:
                        continue

                    plain = crypto.decrypt(raw_content, f)
                    if not plain: continue

                    current_key = session_key.get_session_key(room)
                    if not current_key: continue

                    msg = session_key.decrypt_with_session(plain, current_key)
                    if not msg: continue

                    ts, sender, content = msg.split("|", 2)
                    if sender == nick: continue

                    if raw_type == "SYS":
                        evt = content.replace("SYSTEM:", "")
                        if evt == "joined":
                            state.room_participants.add(sender)
                            buf.append(("System", f"{sender} joined", False))
                            notifications.notify(f"{sender} joined")
                            enqueue_sys(room, nick, "ping", server, f)
                        elif evt == "left":
                            state.room_participants.discard(sender)
                            buf.append(("System", f"{sender} left", False))
                            notifications.notify(f"{sender} left")
                        elif evt == "ping":
                            state.room_participants.add(sender)
                    elif raw_type == "FILEMETA":
                        try:
                            metadata = json.loads(content)
                            file_transfer.handle_file_metadata(metadata, sender, buf)
                        except json.JSONDecodeError: pass
                    elif raw_type == "FILECHUNK":
                        try:
                            chunk_data = json.loads(content)
                            file_transfer.handle_file_chunk(chunk_data, sender, buf)
                        except json.JSONDecodeError: pass
                    else:  # MSG
                        state.room_participants.add(sender)
                        
                        is_mention = f"@{nick}" in content
                        if is_mention:
                            buf.append((sender, content, False, True))
                            notifications.notify_mention(f"You were mentioned by {sender}")
                        else:
                            buf.append((sender, content, False, False))
                            notifications.notify(f"Msg from {sender}")
                    
                    trim(buf)
        except Exception as e:
            # In Tor mode, proxy errors are common if the circuit drops.
            # We want to reconnect silently without logging a scary error.
            if "proxy" not in str(e).lower():
                console.log(f"[yellow]reconnect {e}[/]")
            time.sleep(5)
