import os
import time
import shutil

from . import state, constants, session_key, file_transfer
from .utils import trim
from .network import enqueue_msg

def handle_command(line: str, room: str, nick: str, server: str, f, buf: list):
    """Handles all slash commands."""
    cmd, _, args = line[1:].partition(' ')
    
    if cmd == "exit":
        return "exit" # Signal to exit the main loop

    elif cmd == "clear":
        buf.clear()

    elif cmd == "who":
        state.room_participants.add(nick)
        users = sorted(list(state.room_participants))
        buf.append(("System", f"=== ONLINE ({len(users)}) ===", False))
        for u in users:
            tag = "👑" if u == nick else "●"
            buf.append(("System", f"{tag} {u}", False))
        trim(buf)

    elif cmd == "help":
        help_text = {
            "/help": "Show this help message",
            "/who": "List online users",
            "/stats": "Show message statistics",
            "/security": "Display security information",
            "/server": "Show server information",
            "/notifications": "Toggle desktop notifications",
            "/share <file>": "Share a file (encrypted transfer)",
            "/files": "List available files for download",
            "/download <id>": "Download a file by its ID",
            "/clear": "Clear the message buffer",
            "/exit": "Quit Enchat",
        }
        for c, d in help_text.items():
            buf.append(("System", f"{c}: {d}", False))
        trim(buf)

    elif cmd == "stats":
        tot = len([m for m in buf if m[0] != "System"])
        mine = len([m for m in buf if m[0] == nick])
        buf.append(("System", f"Sent {mine}, Recv {tot-mine}, Total {tot}", False))
        trim(buf)

    elif cmd == "security":
        buf.append(("System", "=== SECURITY STATUS ===", False))
        buf.append(("System", "🔒 Base Encryption: AES-256-Fernet, PBKDF2-SHA256 (100k)", False))
        current_key = session_key.get_session_key(room)
        if current_key:
            key_age = int(time.time() - session_key._active_sessions[room][1])
            rotation_in = session_key.SESSION_KEY_ROTATION_INTERVAL - key_age
            buf.append(("System", f"🔑 Forward Secrecy: Active (key rotates in {rotation_in}s)", False))
        else:
            buf.append(("System", "🔑 Forward Secrecy: Waiting for session key...", False))
        buf.append(("System", f"📁 File Transfers: E2EE chunks ({constants.CHUNK_SIZE//1024}KB) with SHA256 verification", False))
        buf.append(("System", f"🛡️ Keyring: {'Available' if constants.KEYRING_AVAILABLE else 'Not Available'}", False))
        trim(buf)

    elif cmd == "notifications":
        state.notifications_enabled = not state.notifications_enabled
        status = "enabled" if state.notifications_enabled else "disabled"
        buf.append(("System", f"📱 Notifications {status}", False))
        trim(buf)
        
    elif cmd == "files":
        if not state.available_files:
            buf.append(("System", "📂 No files available for download", False))
        else:
            buf.append(("System", f"📂 AVAILABLE FILES ({len(state.available_files)})", False))
            for file_id, info in state.available_files.items():
                meta = info['metadata']
                status = "✅ Ready" if info['complete'] else f"📥 {info['chunks_received']}/{info['total_chunks']}"
                size_mb = meta['size'] / (1024 * 1024)
                display_name = file_transfer.sanitize_filename(meta['filename'], file_id)
                buf.append(("System", f"  {file_id}: {display_name} ({size_mb:.1f}MB) from {info['sender']} - {status}", False))
        trim(buf)
        
    elif cmd == "download":
        file_id = args.strip()
        if not file_id:
            buf.append(("System", "❌ Usage: /download <file_id>", False))
            return
        
        if file_id not in state.available_files:
            buf.append(("System", f"❌ File ID '{file_id}' not found. Use /files.", False))
            return
            
        if not state.available_files[file_id]['complete']:
            info = state.available_files[file_id]
            buf.append(("System", f"❌ File not complete ({info['chunks_received']}/{info['total_chunks']})", False))
            return

        temp_path, error = file_transfer.assemble_file_from_chunks(file_id, f)
        if error:
            buf.append(("System", f"❌ Download failed: {error}", False))
            return

        file_transfer.ensure_downloads_dir()
        filename = file_transfer.sanitize_filename(state.available_files[file_id]['metadata']['filename'], file_id)
        local_path = os.path.join(constants.DOWNLOADS_DIR, filename)

        # Avoid overwriting files
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
            buf.append(("System", f"✅ Downloaded: {os.path.basename(local_path)} ({size_mb:.1f}MB)", False))
            buf.append(("System", f"   📁 Saved to: {rel_path}", False))
            del state.available_files[file_id]
            del state.file_chunks[file_id]
        except Exception as e:
            buf.append(("System", f"❌ Save failed: {e}", False))
            if os.path.exists(temp_path):
                os.remove(temp_path)
        trim(buf)

    elif cmd == "share":
        filepath = os.path.expanduser(args.strip())
        if not filepath:
            buf.append(("System", "❌ Usage: /share <filepath>", False))
            return
        
        buf.append(("System", f"🔍 Preparing to share: {filepath}", False))
        metadata, chunks = file_transfer.split_file_to_chunks(filepath, f)
        if not metadata:
            buf.append(("System", f"❌ {chunks}", False))
            return
        
        file_transfer.enqueue_file_meta(room, nick, metadata, server, f)
        for chunk in chunks:
            file_transfer.enqueue_file_chunk(room, nick, chunk, server, f)
        
        size_mb = metadata['size'] / (1024 * 1024)
        buf.append(("System", f"📤 Sharing: {metadata['filename']} ({size_mb:.1f}MB, {metadata['total_chunks']} chunks)", False))
        trim(buf)

    elif cmd == "server":
        try:
            test_resp = __import__("requests").get(f"{server}/v1/health", timeout=5)
            status = "🟢 Online" if test_resp.status_code == 200 else f"🟡 Status {test_resp.status_code}"
        except Exception:
            status = "🔴 Offline/Unreachable"
        buf.append(("System", f"=== SERVER INFO: {server} ===", False))
        buf.append(("System", f"Status: {status}", False))
        trim(buf)

    else:
        buf.append(("System", f"Unknown command: /{cmd}", False))
        trim(buf)

    return None # No signal
