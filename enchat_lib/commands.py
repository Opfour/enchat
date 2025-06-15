import os
import time
import shutil

from rich.text import Text

from . import state, constants, session_key, file_transfer
from .utils import trim
from .network import enqueue_msg, enqueue_sys

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
