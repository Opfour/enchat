import os
import time
import shutil
import random
import json

from rich.text import Text
from rich.panel import Panel

from . import state, constants, session_key, file_transfer
from .utils import trim
from .network import enqueue_msg, enqueue_sys

# In-memory state for lotteries, keyed by room name
# This is a simple implementation and will reset if the client restarts.
lottery_state = {}

def handle_command(line: str, room: str, nick: str, server: str, f, buf: list, is_public: bool = False, is_tor: bool = False):
    """Handles all slash commands."""
    cmd, _, args = line[1:].partition(' ')
    
    if cmd == "exit":
        return "exit"

    elif cmd == "clear":
        buf.clear()
        buf.append(("System", "[bold yellow]Message buffer cleared.[/]", False))

    elif cmd == "who":
        state.room_participants.add(nick)
        users = sorted(list(state.room_participants))
        buf.append(("System", f"[bold]=== ONLINE ({len(users)}) ===[/]", False))
        for u in users:
            if u == nick:
                buf.append(("System", f"[bold green]👑 {u} (You)[/]", False))
            else:
                buf.append(("System", f"[cyan]● {u}[/]", False))
        trim(buf)

    elif cmd == "help":
        help_text = {
            "/help": "Show this help message.",
            "/who": "List users currently in the room.",
            "/lottery": "Start or participate in a lottery. Use `/lottery help` for details.",
            "/poll": "Create a poll. `/poll \"Q\" | \"A1\" | \"A2\"`",
            "/vote": "Vote in a poll. `/vote <option_number>`",
            "/files": "List available files for download.",
            "/download <id>": "Download a file by its ID.",
            "/share <file>": "Share a file with the room.",
            "/security": "Display security status.",
            "/server": "Show current server info.",
            "/notifications": "Toggle desktop notifications on/off.",
            "/clear": "Clear the message window.",
            "/exit": "Quit Enchat.",
        }
        cli_help = {
            "enchat create": "Create a new private room.",
            "enchat join <room>": "Join a private room.",
            "enchat public <room>": "Join a public room (e.g., lobby).",
            "enchat --reset": "Reset your local configuration."
        }
        buf.append(("System", "[bold]=== In-Chat Commands ===[/]", False))
        for c, d in help_text.items():
            buf.append(("System", f"[bold cyan]{c}[/]: {d}", False))
        
        buf.append(("System", "\n[bold]=== CLI Commands ===[/]", False))
        for c, d in cli_help.items():
            buf.append(("System", f"  [bold cyan]{c}[/]: {d}", False))

        trim(buf)

    elif cmd == "stats":
        total_msgs = len([m for m in buf if m[0] != "System"])
        my_msgs = len([m for m in buf if m[2]]) # m[2] is the 'own' flag
        recv_msgs = total_msgs - my_msgs
        buf.append(("System", f"Messages - Sent: [bold green]{my_msgs}[/], Received: [bold cyan]{recv_msgs}[/], Total: [bold]{total_msgs}[/]", False))
        trim(buf)

    elif cmd == "lottery":
        sub_cmd, _, _ = args.partition(' ')
        sub_cmd = sub_cmd.lower().strip()

        lottery = state.lottery_state.get(room)

        if sub_cmd == "start":
            if lottery:
                buf.append(("System", "[bold yellow]A lottery is already running in this room.[/]", False))
            else:
                # This command is now sent to all users to update their state
                enqueue_sys(room, nick, "LOTTERY_START", server, f)
        
        elif sub_cmd == "enter":
            if not lottery:
                buf.append(("System", "[bold red]There is no active lottery to enter.[/]", False))
            elif nick in lottery["participants"]:
                buf.append(("System", f"[yellow]You have already entered the lottery.[/]", False))
            else:
                enqueue_sys(room, nick, "LOTTERY_ENTER", server, f)
        
        elif sub_cmd == "status":
            if not lottery:
                buf.append(("System", "[bold red]No lottery is currently active.[/]", False))
            else:
                count = len(lottery['participants'])
                participants = sorted(list(lottery['participants']))
                
                status_text = Text()
                status_text.append("Started by: ", style="default")
                status_text.append(lottery['starter'], style="bold cyan")
                status_text.append(f"\nParticipants ({count}):\n", style="default")
                
                if not participants:
                    status_text.append("  (No one has entered yet)", style="dim")
                else:
                    for p in participants:
                        status_text.append(f"  • {p}\n", style="magenta")

                panel = Panel(
                    status_text,
                    title="[bold]🎲 Lottery Status[/]",
                    border_style="blue",
                    padding=(1, 2)
                )
                buf.append(("System", panel, False))

        elif sub_cmd == "draw":
            if not lottery:
                buf.append(("System", "[bold red]There is no active lottery to draw a winner from.[/]", False))
            elif lottery["starter"] != nick:
                buf.append(("System", f"[bold red]Only the lottery starter ([cyan]{lottery['starter']}[/]) can draw a winner.[/]", False))
            elif not lottery["participants"]:
                buf.append(("System", "[bold yellow]There are no participants in the lottery.[/]", False))
            else:
                winner = random.choice(list(lottery["participants"]))
                # Announce winner to everyone
                enqueue_sys(room, nick, f"LOTTERY_WINNER {winner}", server, f)

        elif sub_cmd == "cancel":
            if not lottery:
                buf.append(("System", "[bold red]There is no active lottery to cancel.[/]", False))
            elif lottery["starter"] != nick:
                buf.append(("System", f"[bold red]Only the lottery starter ([cyan]{lottery['starter']}[/]) can cancel it.[/]", False))
            else:
                enqueue_sys(room, nick, "LOTTERY_CANCEL", server, f)
        
        else: # Help for the lottery command
            buf.append(("System", "[bold]🎲 Lottery Commands[/]", False))
            buf.append(("System", "  [bold cyan]/lottery start[/] - Start a new lottery.", False))
            buf.append(("System", "  [bold cyan]/lottery enter[/] - Join the current lottery.", False))
            buf.append(("System", "  [bold cyan]/lottery status[/] - View lottery status.", False))
            buf.append(("System", "  [bold cyan]/lottery draw[/] - Draw a winner (starter only).", False))
            buf.append(("System", "  [bold cyan]/lottery cancel[/] - Cancel the lottery (starter only).", False))
        
        trim(buf)

    elif cmd == "poll":
        poll = state.poll_state.get(room)
        
        # Sub-commands for an existing poll
        if args.lower() == 'status':
            if not poll:
                buf.append(("System", "[bold red]No poll is currently active.[/]", False))
                return
            # The status is now generated dynamically based on the shared state
            # which is updated by the network listener.
            options_text = ""
            total_votes = 0
            for i, option in enumerate(poll['options']):
                vote_count = len(poll['votes'].get(str(i), []))
                total_votes += vote_count
                options_text += f"  [cyan]{i+1}.[/] {option} [bold]({vote_count} votes)[/]\n"
            
            poll_text = Text.from_markup(f"[bold]{poll['question']}[/]\n\n{options_text}\n[dim]Total votes: {total_votes}[/]")
            panel = Panel(poll_text, title="[bold blue]📊 Poll Status[/]", border_style="blue", padding=(1, 2))
            buf.append(("System", panel, False))
            return

        elif args.lower() == 'close':
            if not poll:
                buf.append(("System", "[bold red]No poll to close.[/]", False))
            elif poll['starter'] != nick:
                buf.append(("System", f"[bold red]Only the poll starter ([cyan]{poll['starter']}[/]) can close it.[/]", False))
            else:
                enqueue_sys(room, nick, "POLL_CLOSE", server, f)
            return

        # Create a new poll
        if poll:
            buf.append(("System", "[bold yellow]A poll is already running in this room. Close it first with `/poll close`.[/]", False))
            return

        parts = [p.strip().strip('"') for p in args.split('|')]
        if len(parts) < 3:
            buf.append(("System", "[bold red]Usage: /poll \"Question\" | \"Option 1\" | \"Option 2\"[/]", False))
            return

        question, *options = parts
        if len(options) > 10:
             buf.append(("System", "[bold red]Maximum of 10 options allowed.[/]", False))
             return
        
        poll_data = {"question": question, "options": options}
        enqueue_sys(room, nick, f"POLL_START {json.dumps(poll_data)}", server, f)

    elif cmd == "vote":
        poll = state.poll_state.get(room)
        if not poll:
            buf.append(("System", "[bold red]There is no active poll to vote in.[/]", False))
            return

        try:
            choice = int(args.strip())
            if not (1 <= choice <= len(poll['options'])):
                raise ValueError
        except (ValueError, IndexError):
            buf.append(("System", f"[bold red]Invalid choice. Use a number between 1 and {len(poll['options'])}.[/]", False))
            return
        
        # The check for whether a user has already voted is removed.
        # The listener now handles vote changes correctly by moving the user's vote.
        enqueue_sys(room, nick, f"POLL_VOTE {choice - 1}", server, f)

    elif cmd == "security":
        if is_public:
            buf.append(("System", "[bold]=== 🛡️  PUBLIC ROOM SECURITY ===[/]", False))
            buf.append(("System", Text.from_markup(u"  [yellow]Note: This is a public room. The key is public knowledge.[/]"), False))
            buf.append(("System", Text.from_markup(u"  [bold cyan]├─ Encryption[/]"), False))
            buf.append(("System", Text.from_markup(u"  │  • Transport: [green]Encrypted[/] (Server cannot read messages)"), False))
            buf.append(("System", Text.from_markup(u"  │  • Privacy:   [bold red]NONE[/] (Anyone with the room name can read)"), False))
            
            if is_tor:
                buf.append(("System", Text.from_markup(u"  [bold cyan]├─ Network[/]"), False))
                buf.append(("System", Text.from_markup(u"  │  • Anonymity: [bold purple]Tor Network[/]"), False))
                buf.append(("System", Text.from_markup(f"  │  • Exit IP:   [purple]{state.tor_ip}[/]"), False))

            buf.append(("System", Text.from_markup(u"  [bold cyan]└─ Forward Secrecy[/]"), False))
            buf.append(("System", Text.from_markup(u"     • Status: [bold red]Not available in public rooms[/]"), False))
            trim(buf)
            return

        buf.append(("System", "[bold]=== 🛡️  SECURITY OVERVIEW ===[/]", False))
        
        # --- Network ---
        if is_tor:
            buf.append(("System", Text.from_markup(u"  [bold purple]├─ Network[/]"), False))
            buf.append(("System", Text.from_markup(u"  │  • Anonymity: [bold purple]Tor Network[/]"), False))
            buf.append(("System", Text.from_markup(f"  │  • Exit IP:   [purple]{state.tor_ip}[/]"), False))
        
        # --- Encryption Core ---
        buf.append(("System", Text.from_markup(u"  [bold cyan]├─ Encryption Core[/]"), False))
        buf.append(("System", Text.from_markup(u"  │  • Base Encryption: [green]AES-256-GCM (Fernet)[/green]"), False))
        buf.append(("System", Text.from_markup(u"  │  • Key Derivation:  [green]PBKDF2-SHA256 (100k rounds)[/green]"), False))

        # --- Forward Secrecy ---
        buf.append(("System", Text.from_markup(u"  [bold cyan]├─ Forward Secrecy (PFS)[/]"), False))
        current_key = session_key.get_session_key(room)
        if current_key:
            key_age = int(time.time() - session_key._active_sessions[room][1])
            rotation_in = max(0, session_key.SESSION_KEY_ROTATION_INTERVAL - key_age)
            pfs_status = Text.from_markup(f"  │  • Status:          [bold green]Active[/] (new key in ~{rotation_in}s)")
            buf.append(("System", pfs_status, False))
        else:
            pfs_status = Text.from_markup(u"  │  • Status:          [bold red]Inactive[/] (no session key yet)")
            buf.append(("System", pfs_status, False))
        buf.append(("System", Text.from_markup(u"  │  • Session Key:     [green]Ephemeral, memory-only[/green]"), False))

        # --- Data Privacy & System ---
        buf.append(("System", Text.from_markup(u"  [bold cyan]└─ Data & System[/]"), False))
        chunk_size_kb = constants.CHUNK_SIZE // 1024
        buf.append(("System", Text.from_markup(f"     • File Transfers:  [green]End-to-end encrypted[/green] ({chunk_size_kb}KB chunks)"), False))
        keyring_status_text = "[bold green]Available[/]" if constants.KEYRING_AVAILABLE else "[bold red]Not Available[/]"
        keyring_status = Text.from_markup(f"     • Secure Keyring:  {keyring_status_text}")
        buf.append(("System", keyring_status, False))
        
        trim(buf)

    elif cmd == "notifications":
        state.notifications_enabled = not state.notifications_enabled
        status = "[bold green]enabled[/]" if state.notifications_enabled else "[bold red]disabled[/]"
        buf.append(("System", f"📱 Desktop notifications {status}.", False))
        trim(buf)
        
    elif cmd == "files":
        if not state.available_files:
            buf.append(("System", "📂 No files available for download.", False))
        else:
            buf.append(("System", f"[bold]📂 AVAILABLE FILES ({len(state.available_files)})[/]", False))
            for file_id, info in state.available_files.items():
                meta = info['metadata']
                status = "[green]✅ Ready[/]" if info['complete'] else f"[yellow]📥 {info['chunks_received']}/{info['total_chunks']}[/]"
                size_mb = meta['size'] / (1024 * 1024)
                display_name = file_transfer.sanitize_filename(meta['filename'], file_id)
                buf.append(("System", f"  [bold magenta]{file_id}[/]: {display_name} ({size_mb:.1f}MB) from [cyan]{info['sender']}[/] - {status}", False))
        trim(buf)
        
    elif cmd == "download":
        file_id = args.strip()
        if not file_id:
            buf.append(("System", "[bold red]❌ Usage: /download <file_id>[/]", False))
            return
        
        if file_id not in state.available_files:
            buf.append(("System", f"[bold red]❌ File ID '{file_id}' not found. Use /files.[/]", False))
            return
            
        if not state.available_files[file_id]['complete']:
            info = state.available_files[file_id]
            buf.append(("System", f"[bold red]❌ File not complete ({info['chunks_received']}/{info['total_chunks']})[/]", False))
            return

        temp_path, error = file_transfer.assemble_file_from_chunks(file_id, f)
        if error:
            buf.append(("System", f"[bold red]❌ Download failed: {error}[/]", False))
            return

        file_transfer.ensure_downloads_dir()
        filename = file_transfer.sanitize_filename(state.available_files[file_id]['metadata']['filename'], file_id)
        local_path = os.path.join(constants.DOWNLOADS_DIR, filename)

        counter = 1
        while os.path.exists(local_path):
            name, ext = os.path.splitext(filename)
            local_path = os.path.join(constants.DOWNLOADS_DIR, f"{name}_{counter}{ext}")
            counter += 1

        try:
            shutil.copy2(temp_path, local_path)
            os.remove(temp_path)
            size_mb = state.available_files[file_id]['metadata']['size'] / (1024 * 1024)
            rel_path = os.path.relpath(local_path)
            buf.append(("System", f"[bold green]✅ Downloaded: {os.path.basename(local_path)} ({size_mb:.1f}MB)[/]", False))
            buf.append(("System", f"   [dim]Saved to: {rel_path}[/]", False))
            # --- We keep the file available for others to download ---
            # del state.available_files[file_id]
            # del state.file_chunks[file_id]
        except Exception as e:
            buf.append(("System", f"[bold red]❌ Save failed: {e}[/]", False))
            if os.path.exists(temp_path):
                os.remove(temp_path)
        trim(buf)

    elif cmd == "share":
        filepath = os.path.expanduser(args.strip())
        if not filepath:
            buf.append(("System", "[bold red]❌ Usage: /share <filepath>[/]", False))
            return
        
        if not os.path.exists(filepath):
            buf.append(("System", f"[bold red]❌ File not found: {filepath}[/]", False))
            return

        buf.append(("System", f"🔍 Preparing to share [cyan]{os.path.basename(filepath)}[/]...", False))
        metadata, chunks = file_transfer.split_file_to_chunks(filepath, f)
        if not metadata:
            buf.append(("System", f"[bold red]❌ {chunks}[/]", False)) # chunks contains error
            return
        
        # Enqueue metadata and then chunks
        file_transfer.enqueue_file_meta(room, nick, metadata, server, f)
        for chunk in chunks:
            file_transfer.enqueue_file_chunk(room, nick, chunk, server, f)
        
        size_mb = metadata['size'] / (1024 * 1024)
        buf.append(("System", f"[bold green]📤 Sharing started: {metadata['filename']} ({size_mb:.1f}MB)[/]", False))
        trim(buf)

    elif cmd == "server":
        try:
            test_resp = __import__("requests").get(f"{server}/v1/health", timeout=5)
            status = "[bold green]🟢 Online[/]" if test_resp.status_code == 200 else f"[bold yellow]🟡 Status {test_resp.status_code}[/]"
        except Exception:
            status = "[bold red]🔴 Offline/Unreachable[/]"
        buf.append(("System", f"🌐 Server: [cyan]{server}[/]", False))
        buf.append(("System", f"   Status: {status}", False))
        trim(buf)

    else:
        buf.append(("System", f"[bold red]Unknown command: /{cmd}[/]. Use /help to see available commands.", False))
        trim(buf)

    return None
