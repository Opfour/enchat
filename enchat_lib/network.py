import threading
import time
import queue
import requests
import hashlib
import json
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

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
            # --- Key Rotation Check (for all message types) ---
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
                # This can happen on first message, so we generate a key.
                current_key = session_key.generate_session_key()
                session_key.set_session_key(room, current_key)
                encrypted_key = session_key.encrypt_session_key(current_key, f)
                body = f"SESSIONKEY:{encrypted_key}"
                try:
                    session.post(f"{server}/{room}", data=body, timeout=15)
                except Exception:
                    pass
            
            # --- Message Sending Logic ---
            if kind == "FILE_TRANSFER":
                # Special handler for atomic file transfers
                metadata = payload['metadata']
                chunks = payload['chunks']
                
                # 1. Send metadata
                meta_json = json.dumps(metadata)
                ts = int(time.time())
                msg_to_encrypt = f'{ts}|{nick}|{meta_json}'
                session_encrypted = session_key.encrypt_with_session(msg_to_encrypt, current_key)
                body = f"FILEMETA:{crypto.encrypt(session_encrypted, f)}"
                _send_with_retry(server, room, body, "file metadata", stop_evt)
                
                # 2. Send all chunks using the same key
                for chunk in chunks:
                    chunk_json = json.dumps(chunk)
                    ts = int(time.time())
                    msg_to_encrypt = f'{ts}|{nick}|{chunk_json}'
                    session_encrypted = session_key.encrypt_with_session(msg_to_encrypt, current_key)
                    body = f"FILECHUNK:{crypto.encrypt(session_encrypted, f)}"
                    # We don't retry chunks aggressively to avoid holding up the queue
                    try:
                        session.post(f"{server}/{room}", data=body, timeout=15)
                    except Exception:
                        pass # Ignore chunk send errors for now
                continue

            elif kind in ["MSG", "SYS"]:
                ts = int(time.time())
                content = f"SYSTEM:{payload}" if kind == "SYS" else payload
                msg_to_encrypt = f'{ts}|{nick}|{content}'
                session_encrypted = session_key.encrypt_with_session(msg_to_encrypt, current_key)
                body = f"{kind}:{crypto.encrypt(session_encrypted, f)}"
                _send_with_retry(server, room, body, kind.lower(), stop_evt)

            else:
                continue

        finally:
            state.outbox_queue.task_done()

def _send_with_retry(server, room, body, kind_str, stop_evt):
    """Helper to send a message with a retry mechanism."""
    url = f"{server}/{room}"
    retry, delay = 0, 2
    while retry < 6 and not stop_evt.is_set():
        try:
            r = session.post(url, data=body, timeout=15)
            if r.status_code == 200:
                return
            delay = int(r.headers.get("Retry-After", delay)) if r.status_code == 429 else min(delay * 2, 30)
        except Exception:
            delay = min(delay * 2, 30)
        retry += 1
        time.sleep(delay)

    if retry >= 6:
        console.log(f"[red]✗ could not deliver {kind_str} after retries[/]")

def listener(room, nick, f, server, buf, stop_evt: threading.Event, shutdown_event: threading.Event):
    """Worker thread for listening to SSE events."""
    url = f"{server}/{room}/raw?x-sse=true&since=-30m&poll=65"
    headers = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
    seen: set[str] = set()
    
    # Add self to the participant list with current time
    state.room_participants[nick] = time.time()
    
    while not stop_evt.is_set() and not shutdown_event.is_set():
        try:
            with session.get(url, stream=True, timeout=(5, None), headers=headers) as resp:
                for raw in resp.iter_lines(decode_unicode=True, chunk_size=1):
                    if stop_evt.is_set() or shutdown_event.is_set(): return
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
                    
                    # Allow own SYS messages to be processed to update local state (e.g., for lottery)
                    # but ignore own MSG, FILEMETA, etc., which are handled locally.
                    if sender == nick and raw_type != "SYS":
                        continue

                    if raw_type == "SYS":
                        evt = content.replace("SYSTEM:", "")
                        if evt.startswith("LOTTERY_"):
                            lottery_evt, _, extra = evt.partition(' ')
                            lottery = state.lottery_state.get(room)
                            
                            if lottery_evt == "LOTTERY_START":
                                state.lottery_state[room] = { "starter": sender, "participants": set() }
                                start_text = Text.from_markup(f"[bold cyan]{sender}[/] kicked off a new lottery!\n\nType [bold white on magenta]/lottery enter[/] to join!")
                                panel = Panel(start_text, title="[bold green]🎉 A New Lottery Has Started! 🎉[/]", border_style="green")
                                buf.append(("System", panel, False))
                            
                            elif lottery_evt == "LOTTERY_ENTER":
                                if lottery:
                                    lottery["participants"].add(sender)
                                    buf.append(("System", f"🎟️ [bold magenta]{sender}[/] has entered the lottery!", False))

                            elif lottery_evt == "LOTTERY_CANCEL":
                                if room in state.lottery_state:
                                    del state.lottery_state[room]
                                    cancel_text = Text("The lottery has been canceled.", justify="center")
                                    panel = Panel(cancel_text, title="[bold yellow]Lottery Canceled[/]", border_style="yellow")
                                    buf.append(("System", panel, False))

                            elif lottery_evt == "LOTTERY_WINNER":
                                winner = extra
                                winner_text = Text.from_markup(f"The winning ticket belongs to...\n\n[bold white on magenta] [blink]>>>[/blink] {winner} [blink]<<<[/blink] [/]\n\nCongratulations!", justify="center")
                                panel = Panel(winner_text, title="[bold magenta]🎉 Lottery Winner! 🎉[/]", border_style="magenta")
                                buf.append(("System", panel, False))
                                if room in state.lottery_state:
                                    del state.lottery_state[room]
                            
                        elif evt == "joined":
                            state.room_participants[sender] = time.time()
                            buf.append(("System", f"[dim]{sender} joined[/dim]", False))
                            notifications.notify(f"{sender} joined")
                            enqueue_sys(room, nick, "ping", server, f)
                        elif evt == "left":
                            if sender in state.room_participants:
                                del state.room_participants[sender]
                            buf.append(("System", f"[dim]{sender} left[/dim]", False))
                            notifications.notify(f"{sender} left")

                        elif evt.startswith("FILE_DOWNLOAD"):
                            _, _, file_id = evt.partition(' ')
                            if file_id in state.available_files:
                                filename = state.available_files[file_id]['metadata']['filename']
                                buf.append(("System", f"📥 [bold cyan]{sender}[/] downloaded file \"{escape(filename)}\" ([dim]{file_id}[/dim])", False))
                            else:
                                buf.append(("System", f"📥 [bold cyan]{sender}[/] downloaded file [dim]{file_id}[/dim]", False))

                        elif evt.startswith("POLL_"):
                            poll_evt, _, extra = evt.partition(' ')

                            if poll_evt == "POLL_START":
                                try:
                                    poll_data = json.loads(extra)
                                    state.poll_state[room] = {
                                        "starter": sender,
                                        "question": poll_data["question"],
                                        "options": poll_data["options"],
                                        "votes": {} # { 'option_index': {'user1', 'user2'} }
                                    }
                                    
                                    options_text = ""
                                    for i, option in enumerate(poll_data['options']):
                                        options_text += f"  [cyan]{i+1}.[/] {option}\n"

                                    poll_text = Text.from_markup(f"[bold]{poll_data['question']}[/]\n\n{options_text}\n[dim]Vote with /vote <number>[/dim]")
                                    panel = Panel(poll_text, title=f"📊 [bold blue]Poll Started by {sender}[/]", border_style="blue", padding=(1, 2))
                                    buf.append(("System", panel, False))
                                except json.JSONDecodeError:
                                    pass
                            
                            elif poll_evt == "POLL_VOTE":
                                poll = state.poll_state.get(room)
                                if poll:
                                    choice = extra.strip()
                                    # Remove previous vote if any
                                    for votes in poll['votes'].values():
                                        votes.discard(sender)
                                    # Add new vote
                                    if choice not in poll['votes']:
                                        poll['votes'][choice] = set()
                                    poll['votes'][choice].add(sender)
                                    
                                    option_text = poll['options'][int(choice)]
                                    buf.append(("System", f"🗳️ [bold blue]{sender}[/] voted for: [italic]'{option_text}'[/]", False))

                            elif poll_evt == "POLL_CLOSE":
                                poll = state.poll_state.get(room)
                                if poll:
                                    # Calculate final results
                                    options_text = ""
                                    winner_text = ""
                                    max_votes = 0
                                    
                                    sorted_votes = sorted(
                                        [(len(v), k) for k, v in poll['votes'].items()],
                                        reverse=True
                                    )
                                    if sorted_votes:
                                        max_votes = sorted_votes[0][0]

                                    for i, option in enumerate(poll['options']):
                                        vote_count = len(poll['votes'].get(str(i), []))
                                        is_winner = vote_count == max_votes and max_votes > 0
                                        
                                        bar = "█" * vote_count
                                        line = f"  [cyan]{i+1}.[/] {option} [bold]({vote_count})[/] "
                                        if is_winner:
                                            line = f"🏆{line}"
                                            winner_text += f"[bold magenta]{option}[/] "
                                        options_text += line + f"[green]{bar}[/]\n"

                                    final_text = Text.from_markup(f"[bold]{poll['question']}[/]\n\n{options_text}\n[bold]Winner(s): {winner_text}[/]")
                                    panel = Panel(final_text, title="[bold blue]📊 Poll Closed - Final Results[/]", border_style="blue", padding=(1, 2))
                                    buf.append(("System", panel, False))
                                    del state.poll_state[room]

                        elif evt == "ping":
                            state.room_participants[sender] = time.time()
                    elif raw_type == "FILEMETA":
                        try:
                            metadata = json.loads(content)
                            file_transfer.handle_file_metadata(metadata, sender, buf)
                        except (json.JSONDecodeError, KeyError): pass
                    elif raw_type == "FILECHUNK":
                        try:
                            chunk_data = json.loads(content)
                            file_transfer.handle_file_chunk(chunk_data, sender, buf)
                        except (json.JSONDecodeError, KeyError): pass
                    else:  # MSG
                        state.room_participants[sender] = time.time()
                        
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
