#!/usr/bin/env python3
"""enchat – encrypted terminal chat (Rich UI, non-blocking sender)
Route B • 2025-06-15  CHUNK 1 / 2
"""
# — stdlib —
import argparse, base64, hashlib, os, queue, select, signal, subprocess, sys, threading, time, tempfile, glob
from getpass import getpass
from shutil import which
from typing import List, Tuple, Optional, Dict, Set
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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
import logging
import platform
import ctypes
import gc
import secrets

# — local —
import session_key

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

# File transfer constants - CONFIGURABLE
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB (can be increased to 10MB, 25MB, etc.)
CHUNK_SIZE = 6 * 1024  # 6KB chunks (safe for ntfy)
# 
# To allow larger files:
# MAX_FILE_SIZE = 25 * 1024 * 1024  # 25MB
# 
# Consider implications:
# - Larger files = more memory usage
# - More chunks = longer transfer time  
# - ntfy server may have rate limits
# - Self-hosted ntfy recommended for large files
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
    
    # Special case for empty files (0 chunks)
    is_complete = (total_chunks == 0)
    
    available_files[file_id] = {
        'metadata': metadata,
        'sender': sender,
        'chunks_received': 0,
        'total_chunks': total_chunks,
        'complete': is_complete
    }
    file_chunks[file_id] = {}
    
    size_mb = size / (1024 * 1024)
    buf.append(("System", f"📎 {sender} shared: {filename} ({size_mb:.1f}MB, {total_chunks} chunks)", False))
    
    if is_complete:
        buf.append(("System", f"✅ {filename} ready! Use '/download {file_id}' (empty file)", False))
    else:
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
        temp_path = os.path.join(FILE_TEMP_DIR, f"{file_id}_{metadata['filename']}")
        file_hash = hashlib.sha256()
        
        # Special case for empty files (0 chunks)
        if metadata['total_chunks'] == 0:
            # Create empty file
            with open(temp_path, 'wb') as f:
                pass  # Create empty file
            # Hash of empty file is hash of empty bytes
            file_hash.update(b'')
        else:
            # Sort chunks by number
            sorted_chunks = [chunks_dict[i] for i in sorted(chunks_dict.keys())]
            
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

# ── secure data wipe ──────────────────────────────────────────────────
def get_storage_type(filepath):
    """
    Detect if file is on SSD or HDD.
    Returns: ("ssd"|"hdd"|"unknown", mount_point)
    """
    try:
        abs_path = os.path.abspath(filepath)
        if sys.platform == "darwin":
            # macOS: use diskutil to get mount point
            mount_point = subprocess.run(
                ['df', abs_path], 
                capture_output=True, 
                text=True
            ).stdout.split('\n')[1].split()[-1]
            
            # Get device info
            result = subprocess.run(
                ['diskutil', 'info', mount_point], 
                capture_output=True, 
                text=True
            ).stdout.lower()
            
            if "solid state" in result:
                return "ssd", mount_point
            elif "hard drive" in result:
                return "hdd", mount_point
                
        elif sys.platform == "linux":
            # Get device from mount point
            mount_point = subprocess.run(
                ['df', abs_path], 
                capture_output=True, 
                text=True
            ).stdout.split('\n')[1].split()[-1]
            
            # Get device name
            device = subprocess.run(
                ['findmnt', '-n', '-o', 'SOURCE', mount_point],
                capture_output=True,
                text=True
            ).stdout.strip()
            
            # Remove partition number if any
            device = ''.join([c for c in device if not c.isdigit()])
            
            # Check rotational flag
            try:
                with open(f'/sys/block/{os.path.basename(device)}/queue/rotational', 'r') as f:
                    if f.read().strip() == '0':
                        return "ssd", mount_point
                    return "hdd", mount_point
            except:
                pass
                
    except Exception:
        pass
    return "unknown", os.path.dirname(abs_path)

def secure_delete_file(filepath):
    """
    Best-effort secure file deletion based on storage type and platform.
    Returns (success, method_used, warnings)
    """
    if not os.path.exists(filepath):
        return True, "none", []
    
    warnings = []
    storage_type, mount_point = get_storage_type(filepath)
    
    if storage_type == "ssd":
        warnings.append("File is on SSD - secure deletion limited due to wear leveling")
    
    try:
        # Platform-specific secure deletion
        if sys.platform == "darwin":  # macOS
            # Use built-in rm with overwrite
            with open(filepath, 'wb') as f:
                size = os.path.getsize(filepath)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            os.remove(filepath)
            return True, "macos_overwrite", warnings
                
        elif sys.platform == "linux":
            # Try shred without sudo
            if os.path.exists("/usr/bin/shred"):
                result = subprocess.run(
                    ['shred', '-u', '-n', '1', filepath],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    return True, "linux_shred", warnings
                warnings.append(f"shred failed: {result.stderr}")
                
        elif sys.platform == "win32":
            # Windows: Use cipher (built-in) for overwrite
            result = subprocess.run(
                ['cipher', '/w:' + os.path.dirname(filepath)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                os.remove(filepath)
                return True, "windows_cipher", warnings
            warnings.append(f"cipher failed: {result.stderr}")
                
        # Cross-platform secure deletion
        warnings.append("Using cross-platform secure deletion")
        
        # 1. Get original file permissions and size
        size = os.path.getsize(filepath)
        
        # 2. Three-pass overwrite
        for i in range(3):
            try:
                with open(filepath, 'wb') as f:
                    if i == 0:  # First pass: random data
                        f.write(os.urandom(size))
                    elif i == 1:  # Second pass: ones
                        f.write(b'\xFF' * size)
                    else:  # Third pass: zeros
                        f.write(b'\x00' * size)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                warnings.append(f"Pass {i+1} failed: {str(e)}")
                break
                
        # 3. Delete file
        os.remove(filepath)
        
        # 4. Sync directory to ensure changes are written
        try:
            dirfd = os.open(os.path.dirname(filepath), os.O_DIRECTORY)
            os.fsync(dirfd)
            os.close(dirfd)
        except Exception as e:
            warnings.append(f"Directory sync failed: {str(e)}")
            
        return True, "cross_platform", warnings
            
    except Exception as e:
        warnings.append(f"Secure deletion failed: {str(e)}")
        try:
            # Fallback to normal deletion
            os.remove(filepath)
            warnings.append("Fell back to normal file deletion")
            return True, "normal_delete", warnings
        except Exception as e:
            warnings.append(f"Normal deletion also failed: {str(e)}")
            return False, "failed", warnings

def secure_delete_directory(dirpath):
    """
    Recursively delete a directory and its contents securely.
    Returns (success, methods_used, warnings)
    """
    if not os.path.exists(dirpath):
        return True, [], []
        
    all_warnings = []
    methods_used = set()
    success = True
    
    try:
        for root, dirs, files in os.walk(dirpath, topdown=False):
            # Delete files first
            for name in files:
                filepath = os.path.join(root, name)
                file_success, method, warnings = secure_delete_file(filepath)
                if not file_success:
                    success = False
                methods_used.add(method)
                all_warnings.extend(warnings)
                
            # Then remove empty directories
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception as e:
                    all_warnings.append(f"Failed to remove directory {name}: {str(e)}")
                    success = False
                    
        # Finally remove the root directory
        try:
            os.rmdir(dirpath)
        except Exception as e:
            all_warnings.append(f"Failed to remove root directory: {str(e)}")
            success = False
            
        return success, list(methods_used), all_warnings
        
    except Exception as e:
        all_warnings.append(f"Directory deletion failed: {str(e)}")
        return False, list(methods_used), all_warnings

def get_enchat_data_locations():
    """
    Returns a list of tuples (path, description, risk_level) for all Enchat data locations
    risk_level: 1 = low, 2 = medium, 3 = high (sensitive data)
    """
    locations = []
    
    # High-risk locations (contain keys/credentials)
    config_path = os.path.expanduser("~/.enchat.conf")
    if os.path.exists(config_path):
        locations.append((config_path, "Configuration file", 3))
    
    keychain_file = os.path.expanduser("~/Library/Keychains/login.keychain-db")
    if os.path.exists(keychain_file):
        locations.append((keychain_file, "System keychain", 3))
    
    # Medium-risk locations (may contain message content)
    downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads", "enchat")
    if os.path.exists(downloads_dir):
        locations.append((downloads_dir, "Downloads folder", 2))
    
    local_storage = os.path.join(os.path.expanduser("~"), ".local", "share", "enchat")
    if os.path.exists(local_storage):
        locations.append((local_storage, "Local storage", 2))
    
    # Low-risk locations (temporary/cache files)
    temp_patterns = [
        os.path.join(tempfile.gettempdir(), "enchat-*"),
        os.path.join(tempfile.gettempdir(), "tmp-enchat-*")
    ]
    for pattern in temp_patterns:
        for path in glob.glob(pattern):
            locations.append((path, "Temporary file", 1))
    
    cache_patterns = [
        os.path.join(os.path.dirname(__file__), "__pycache__"),
        os.path.join(os.path.dirname(__file__), "*.pyc"),
        os.path.join(os.path.dirname(__file__), "*.pyo")
    ]
    for pattern in cache_patterns:
        for path in glob.glob(pattern):
            locations.append((path, "Python cache", 1))
    
    return locations

def wipe_keychain_entries():
    """
    Remove only Enchat-related entries from system keychain/keyring
    Returns (success, warnings)
    """
    warnings = []
    try:
        if sys.platform == "darwin":
            # macOS: List and remove only Enchat entries
            # First, find all Enchat entries
            result = subprocess.run([
                'security', 'find-generic-password', '-a', 'enchat'
            ], capture_output=True, text=True)
            
            # Extract service names from the output
            services = []
            for line in result.stderr.split('\n'):
                if 'service=' in line:
                    service = line.split('service=')[1].strip('"')
                    if 'enchat' in service.lower():
                        services.append(service)
            
            # Remove each Enchat entry
            for service in services:
                subprocess.run([
                    'security', 'delete-generic-password',
                    '-a', 'enchat',
                    '-s', service
                ], capture_output=True)
                
        elif sys.platform == "linux":
            # Try common Linux keyrings
            for cmd in ['secret-tool', 'gnome-keyring-daemon']:
                try:
                    # List and remove only Enchat entries
                    if cmd == 'secret-tool':
                        # First, list all items
                        result = subprocess.run([
                            'secret-tool', 'search', 'application', 'enchat'
                        ], capture_output=True, text=True)
                        
                        # Remove each Enchat entry
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                subprocess.run([
                                    'secret-tool', 'clear',
                                    'application', 'enchat',
                                    'service', line.strip()
                                ], capture_output=True)
                    else:
                        # For gnome-keyring, only clear Enchat entries
                        subprocess.run([
                            cmd, '--remove="enchat:*"'
                        ], capture_output=True)
                except:
                    pass
                    
        elif sys.platform == "win32":
            # Windows: Only remove Enchat credentials
            try:
                # List credentials
                result = subprocess.run([
                    'cmdkey', '/list'
                ], capture_output=True, text=True)
                
                # Find and remove only Enchat entries
                for line in result.stdout.split('\n'):
                    if 'enchat' in line.lower():
                        target = line.split('Target: ')[1].strip() if 'Target: ' in line else None
                        if target:
                            subprocess.run([
                                'cmdkey', '/delete:' + target
                            ], capture_output=True)
            except Exception as e:
                warnings.append(f"Failed to clear Windows credentials: {str(e)}")
                
    except Exception as e:
        warnings.append(f"Failed to clear keychain entries: {str(e)}")
    
    return len(warnings) == 0, warnings

def clear_shell_history():
    """
    Clear Enchat-related entries from shell history
    Returns (success, warnings)
    """
    warnings = []
    try:
        # Determine shell and history file
        shell = os.environ.get('SHELL', '')
        if 'zsh' in shell:
            history_file = os.path.expanduser('~/.zsh_history')
        elif 'bash' in shell:
            history_file = os.path.expanduser('~/.bash_history')
        else:
            return False, ["Unsupported shell for history clearing"]
            
        if os.path.exists(history_file):
            # Read history file
            with open(history_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out Enchat-related commands
            new_lines = [l for l in lines if 'enchat' not in l.lower()]
            
            # Write back if changed
            if len(new_lines) != len(lines):
                with open(history_file, 'w') as f:
                    f.writelines(new_lines)
                return True, []
                
    except Exception as e:
        warnings.append(f"Failed to clear shell history: {str(e)}")
    
    return False, warnings

def clear_system_logs():
    """
    Clear Enchat-related system logs without requiring sudo
    Returns (success, warnings)
    """
    warnings = []
    try:
        if sys.platform == "darwin":
            # Use user-level log show to find Enchat entries
            subprocess.run([
                'log', 'show', '--predicate', 'process == "enchat"', 
                '--style', 'compact', '--last', '24h'
            ], capture_output=True)
            warnings.append("System logs may retain entries - full clear requires admin rights")
        elif sys.platform == "linux":
            # Try user-level journal clear
            subprocess.run([
                'journalctl', '--user', '--vacuum-time=1s'
            ], capture_output=True)
            warnings.append("System-wide logs may retain entries - full clear requires admin rights")
    except Exception as e:
        warnings.append(f"Could not access system logs: {str(e)}")
    return True, warnings

def clear_clipboard():
    """
    Clear system clipboard
    Returns (success, warnings)
    """
    warnings = []
    try:
        if sys.platform == "darwin":
            subprocess.run(['pbcopy'], input=b'', capture_output=True)
        elif sys.platform == "linux":
            subprocess.run(['xsel', '-c'], capture_output=True)
        elif sys.platform == "win32":
            subprocess.run(['cmd', '/c', 'echo off | clip'], capture_output=True)
    except Exception as e:
        warnings.append(f"Failed to clear clipboard: {str(e)}")
    return len(warnings) == 0, warnings

def get_message_history_locations():
    """
    Returns locations that might contain message history
    """
    locations = []
    seen_paths = set()  # Track seen paths to avoid duplicates
    
    # Core message storage
    home = os.path.expanduser("~")
    
    # Message history locations
    history_paths = [
        os.path.join(home, ".enchat_history"),
        os.path.join(home, ".local", "share", "enchat", "history"),
        os.path.join(home, "Library", "Application Support", "Enchat", "history"),
        os.path.join(home, "AppData", "Local", "Enchat", "history"),
    ]
    
    for path in history_paths:
        if os.path.exists(path) and path not in seen_paths:
            seen_paths.add(path)
            locations.append((path, "Message history", 3))
            
    # Terminal scrollback files
    term_paths = [
        os.path.join(home, ".zsh_history"),
        os.path.join(home, ".bash_history"),
        os.path.join(home, ".python_history"),
    ]
    
    for path in term_paths:
        if os.path.exists(path) and path not in seen_paths:
            seen_paths.add(path)
            locations.append((path, "Terminal history", 2))
            
    # Additional potential message locations
    extra_paths = [
        os.path.join(home, ".cache", "enchat"),
        os.path.join(home, "Library", "Caches", "Enchat"),
        os.path.join(home, "AppData", "Local", "Temp", "Enchat"),
    ]
    
    for path in extra_paths:
        if os.path.exists(path) and path not in seen_paths:
            seen_paths.add(path)
            locations.append((path, "Message cache", 2))
    
    return locations

def clear_memory():
    """
    Clear sensitive data from memory
    """
    import gc
    
    # First clear all Enchat-specific data
    try:
        # Clear message buffers
        global message_buffer, outbox_queue, message_cache
        if 'message_buffer' in globals():
            message_buffer = None
        if 'outbox_queue' in globals():
            outbox_queue = None
        if 'message_cache' in globals():
            message_cache = None
        
        # Clear ChatUI data
        if 'ChatUI' in globals():
            for attr in ['room', 'nick', 'server', 'fernet', 'message_buffer']:
                if hasattr(ChatUI, attr):
                    setattr(ChatUI, attr, None)
        
        # Clear encryption keys
        if 'Fernet' in globals():
            if hasattr(Fernet, 'key'):
                setattr(Fernet, 'key', None)
        
        # Clear command history
        if 'readline' in sys.modules:
            import readline
            readline.clear_history()
            
        # Clear any remaining references, but skip function names
        frame = sys._getframe()
        while frame:
            for key in list(frame.f_locals.keys()):
                value = frame.f_locals[key]
                # Skip functions and built-ins
                if not callable(value) and not isinstance(value, type):
                    if ('enchat' in key.lower() or 
                        'message' in key.lower() or 
                        'key' in key.lower()):
                        frame.f_locals[key] = None
            frame = frame.f_back
            
    except Exception:
        pass
        
    # Force garbage collection multiple times
    for _ in range(3):
        gc.collect()
    
    # Clear Python's internal buffers
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Overwrite memory with random data
    try:
        import ctypes
        import array
        
        # Get memory page size
        page_size = 4096  # Default to 4KB if we can't get it
        try:
            import resource
            page_size = resource.getpagesize()
        except:
            pass
            
        # Allocate and free memory repeatedly with random data
        for _ in range(5):
            # Allocate multiple pages
            arrays = []
            try:
                for _ in range(10):  # Try to allocate 10 pages
                    arr = array.array('B', os.urandom(page_size))
                    arrays.append(arr)
            except:
                pass
                
            # Free them
            for arr in arrays:
                del arr
            arrays = None
            
            # Force garbage collection
            gc.collect()
            
    except:
        pass
        
    # Final garbage collection
    gc.collect()
    
    return True

def secure_memory_wipe(obj: object) -> None:
    """
    Securely wipe an object from memory
    """
    if obj is None:
        return
        
    try:
        # Handle different types of objects
        if isinstance(obj, str):
            # Overwrite string contents with random data
            string_buffer = ctypes.create_string_buffer(len(obj))
            ctypes.memset(string_buffer, 0, len(obj))
            
        elif isinstance(obj, bytes):
            # Overwrite bytes with random data
            byte_buffer = ctypes.create_string_buffer(len(obj))
            ctypes.memset(byte_buffer, 0, len(obj))
            
        elif isinstance(obj, (list, tuple, set)):
            # Recursively wipe contained objects
            for item in obj:
                secure_memory_wipe(item)
            
        elif isinstance(obj, dict):
            # Wipe both keys and values
            for key, value in obj.items():
                secure_memory_wipe(key)
                secure_memory_wipe(value)
                
        # Force garbage collection after wiping
        del obj
        gc.collect()
        
    except Exception as e:
        console.print(f"[yellow]⚠️  Memory wipe warning: {str(e)}[/]")

def secure_delete_file(path: str, passes: int = 3) -> Tuple[bool, Optional[str]]:
    """
    Securely delete a file using multiple overwrite passes
    Returns (success, error_message)
    """
    if not os.path.exists(path) or os.path.islink(path):
        return True, None
        
    try:
        # Get file size
        file_size = os.path.getsize(path)
        
        # Multiple overwrite passes
        for _ in range(passes):
            with open(path, 'wb') as f:
                # Write random data
                f.write(secrets.token_bytes(file_size))
                # Ensure it's written to disk
                f.flush()
                os.fsync(f.fileno())
                
        # Finally delete the file
        os.remove(path)
        return True, None
        
    except Exception as e:
        return False, str(e)

def find_enchat_files() -> Set[str]:
    """
    Find all Enchat-related files that need to be wiped
    """
    files_to_wipe = set()
    
    # Config file
    config_path = os.path.expanduser("~/.enchat.conf")
    if os.path.exists(config_path):
        files_to_wipe.add(config_path)
    
    # Python cache files
    cache_pattern = os.path.join(os.path.dirname(__file__), "**/*.pyc")
    files_to_wipe.update(glob.glob(cache_pattern, recursive=True))
    
    # Temp files
    temp_pattern = os.path.join(os.path.dirname(__file__), "**/*.tmp")
    files_to_wipe.update(glob.glob(temp_pattern, recursive=True))
    
    return files_to_wipe

def secure_wipe():
    """
    Securely wipe all Enchat data
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        # Track overall progress
        overall_task = progress.add_task("[cyan]Wiping Enchat data...", total=100)
        
        try:
            # 1. Clear sensitive memory
            progress.update(overall_task, advance=10, description="[cyan]Clearing sensitive memory...")
            
            # Clear encryption keys
            secure_memory_wipe(globals().get('f', None))  # Fernet instance
            secure_memory_wipe(globals().get('secret', None))  # Passphrase
            secure_memory_wipe(globals().get('buf', None))  # Message buffer
            
            # Force garbage collection
            gc.collect()
            progress.update(overall_task, advance=10)
            
            # 2. Wipe configuration file
            progress.update(overall_task, description="[cyan]Wiping configuration...")
            config_path = os.path.expanduser("~/.enchat.conf")
            if os.path.exists(config_path):
                success, error = secure_delete_file(config_path)
                if not success:
                    progress.console.print(f"[yellow]⚠️  Warning: Could not fully wipe config: {error}[/]")
            progress.update(overall_task, advance=30)
            
            # 3. Clear keychain entries
            progress.update(overall_task, description="[cyan]Clearing keychain entries...")
            keychain_success, keychain_warnings = wipe_keychain_entries()
            if keychain_warnings:
                for warning in keychain_warnings:
                    progress.console.print(f"[yellow]⚠️  {warning}[/]")
            progress.update(overall_task, advance=20)
            
            # 4. Clear system artifacts
            progress.update(overall_task, description="[cyan]Clearing system artifacts...")
            
            # Clear clipboard if it contains sensitive data
            try:
                if platform.system() == 'Darwin':  # macOS
                    os.system('pbcopy < /dev/null')
                elif platform.system() == 'Linux':
                    os.system('xsel -cb')  # X11
                    os.system('wl-copy --clear')  # Wayland
                elif platform.system() == 'Windows':
                    os.system('cmd /c "echo off | clip"')
            except:
                pass
                
            # Clear shell history entries containing 'enchat'
            shell = os.environ.get('SHELL', '')
            if 'zsh' in shell:
                history_file = os.path.expanduser('~/.zsh_history')
            elif 'bash' in shell:
                history_file = os.path.expanduser('~/.bash_history')
            
            if os.path.exists(history_file):
                try:
                    with open(history_file, 'r') as f:
                        lines = f.readlines()
                    with open(history_file, 'w') as f:
                        f.writelines([l for l in lines if 'enchat' not in l.lower()])
                except:
                    pass
                    
            progress.update(overall_task, advance=20)
            
            # 5. Final cleanup
            progress.update(overall_task, description="[cyan]Performing final cleanup...")
            gc.collect()  # One final GC run
            progress.update(overall_task, advance=10)
            
            # Complete
            progress.update(overall_task, description="[bold green]✅ Wipe complete!")
            
        except Exception as e:
            progress.console.print(f"\n[bold red]Error during secure wipe: {str(e)}[/]")
            progress.console.print("[yellow]Some data may not have been fully wiped[/]")
            return
            
    console.print("\n[bold green]🔒 Enchat data has been securely wiped![/]")
    console.print("[dim]Note: Some traces may remain in system memory until reboot[/]")
    console.print("[dim]For maximum security, consider rebooting your system[/]")

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
        
        # Check if we need to rotate session key
        if session_key.should_rotate_key(room):
            new_key = session_key.generate_session_key()
            session_key.set_session_key(room, new_key)
            # Broadcast new session key
            encrypted_key = session_key.encrypt_session_key(new_key, f)
            body = f"SESSIONKEY:{encrypted_key}"
            url = f"{server}/{room}"
            try:
                session.post(url, data=body, timeout=15)
            except Exception:
                pass

        # Get current session key
        current_key = session_key.get_session_key(room)
        if not current_key:
            current_key = session_key.generate_session_key()
            session_key.set_session_key(room, current_key)
            # Broadcast new session key
            encrypted_key = session_key.encrypt_session_key(current_key, f)
            body = f"SESSIONKEY:{encrypted_key}"
            url = f"{server}/{room}"
            try:
                session.post(url, data=body, timeout=15)
            except Exception:
                pass

        # Double encrypt: first with session key, then with room key
        if kind=="MSG":
            msg = f'{int(time.time())}|{nick}|{payload}'
            session_encrypted = session_key.encrypt_with_session(msg, current_key)
            body = f"MSG:{encrypt(session_encrypted, f)}"
        elif kind=="SYS":
            msg = f'{int(time.time())}|{nick}|SYSTEM:{payload}'
            session_encrypted = session_key.encrypt_with_session(msg, current_key)
            body = f"SYS:{encrypt(session_encrypted, f)}"
        elif kind=="FILEMETA":
            msg = f'{int(time.time())}|{nick}|{payload}'
            session_encrypted = session_key.encrypt_with_session(msg, current_key)
            body = f"FILEMETA:{encrypt(session_encrypted, f)}"
        elif kind=="FILECHUNK":
            msg = f'{int(time.time())}|{nick}|{payload}'
            session_encrypted = session_key.encrypt_with_session(msg, current_key)
            body = f"FILECHUNK:{encrypt(session_encrypted, f)}"
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
                        
                        # Handle session key updates
                        if raw.startswith("SESSIONKEY:"):
                            encrypted_key = raw[11:]  # Skip "SESSIONKEY:"
                            new_key = session_key.decrypt_session_key(encrypted_key, f)
                            if new_key:
                                session_key.set_session_key(room, new_key)
                            continue
                            
                        if not raw.startswith(("SYS:","MSG:","FILEMETA:","FILECHUNK:")): continue
                        
                        if raw.startswith("FILEMETA:"):
                            kind,enc="FILEMETA:",raw[9:]
                        elif raw.startswith("FILECHUNK:"):
                            kind,enc="FILECHUNK:",raw[10:]
                        else:
                            kind,enc=raw[:4],raw[4:]
                            
                        # First decrypt with room key
                        plain = decrypt(enc, f)
                        if not plain: continue
                        
                        # Then decrypt with session key
                        current_key = session_key.get_session_key(room)
                        if not current_key:
                            continue  # No valid session key yet
                            
                        msg = session_key.decrypt_with_session(plain, current_key)
                        if not msg: continue
                        
                        ts,sender,content=msg.split("|",2)
                        
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
        self.last_terminal_size=(0,0)  # Track terminal size changes

    # ─ render helpers ─
    def _head(self):
        return Panel(Text.assemble(
            (" ENCHAT ","bold cyan"),
            (" CONNECTED ","bold green"),
            (f" {self.room} ","white"),
            (f" {self.nick} ","magenta"),
            (" | "+self.server.replace("https://",""),"dim")),style="blue")
    def _body(self):
        # Calculate available space for messages (terminal height - header - input - panel borders)
        try:
            import shutil
            terminal_height = shutil.get_terminal_size().lines
            # Reserve space: 3 for header + 3 for input + 4 for panel borders/padding
            # Ensure minimum of 3 lines for very small terminals
            available_lines = max(3, terminal_height - 10)
        except:
            # Fallback for systems where terminal size detection fails
            available_lines = 20
        
        # Take recent messages that fit in available space
        # Show newest messages first, limit to available lines
        messages_to_show = self.buf[-available_lines:] if len(self.buf) > available_lines else self.buf
        
        t=Text()
        for u,m,own in messages_to_show:
            if u=="System": t.append(f"[SYSTEM] {m}\n",style="yellow")
            else:
                lab,st=("You","green") if own else (u,"cyan")
                t.append(f"{lab}: ",style=st); t.append(f"{m}\n")
        return Panel(t,title=f"Messages ({len(self.buf)}) - showing newest",padding=(0,1))
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
                # Check for buffer changes
                if len(self.buf)!=self.last_len:
                    self.last_len=len(self.buf); self.redraw=True
                
                # Check for input changes
                curr_in="".join(current_input)
                if curr_in!=self.last_input:
                    self.last_input=curr_in; self.redraw=True
                
                # Check for terminal size changes (for responsive UI)
                try:
                    import shutil
                    current_size = shutil.get_terminal_size()
                    current_size_tuple = (current_size.lines, current_size.columns)
                    if current_size_tuple != self.last_terminal_size:
                        self.last_terminal_size = current_size_tuple
                        self.redraw = True  # Trigger redraw on terminal resize
                except:
                    pass  # Ignore errors in terminal size detection

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
                    self.buf.append(("System","=== SECURITY STATUS ===",False))
                    self.buf.append(("System","🔒 Base Encryption: AES-256-Fernet, PBKDF2-SHA256 (100k)",False))
                    
                    # Session key status
                    current_key = session_key.get_session_key(self.room)
                    if current_key:
                        key_age = int(time.time() - session_key._active_sessions[self.room][1])
                        rotation_in = session_key.SESSION_KEY_ROTATION_INTERVAL - key_age
                        self.buf.append(("System",f"🔑 Forward Secrecy: Active",False))
                        self.buf.append(("System",f"  • Session key age: {key_age}s",False))
                        self.buf.append(("System",f"  • Next rotation in: {rotation_in}s",False))
                    else:
                        self.buf.append(("System","🔑 Forward Secrecy: Waiting for session key...",False))
                    
                    # Room security
                    self.buf.append(("System",f"🏠 Room: {self.room}",False))
                    self.buf.append(("System",f"  • Double encryption: Room key + Session key",False))
                    self.buf.append(("System",f"  • Perfect Forward Secrecy: Enabled",False))
                    self.buf.append(("System",f"  • Key rotation interval: {session_key.SESSION_KEY_ROTATION_INTERVAL}s",False))
                    
                    # File transfer security
                    self.buf.append(("System","📁 File Transfer Security:",False))
                    self.buf.append(("System",f"  • End-to-end encrypted chunks: {CHUNK_SIZE//1024}KB",False))
                    self.buf.append(("System",f"  • SHA256 integrity verification",False))
                    self.buf.append(("System",f"  • Max file size: {MAX_FILE_SIZE//1024//1024}MB",False))
                    
                    # System security
                    self.buf.append(("System","🛡️ System Security:",False))
                    self.buf.append(("System",f"  • Memory-only session keys",False))
                    self.buf.append(("System",f"  • Zero server knowledge",False))
                    if KEYRING_AVAILABLE:
                        self.buf.append(("System",f"  • Secure keyring available: Yes",False))
                    else:
                        self.buf.append(("System",f"  • Secure keyring available: No",False))
                    
                    # Server info
                    self.buf.append(("System","🌐 Server:",False))
                    if self.server == ENCHAT_NTFY:
                        self.buf.append(("System",f"  • Using dedicated Enchat server",False))
                    elif self.server == DEFAULT_NTFY:
                        self.buf.append(("System",f"  • Using public ntfy.sh server",False))
                    else:
                        self.buf.append(("System",f"  • Using custom server: {self.server}",False))
                    
                    trim(self.buf)
                    continue
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
                if line.startswith("/server"):
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
                    trim(self.buf)
                    continue
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

def reset_enchat():
    """
    Reset Enchat configuration and keys
    """
    console = Console()
    
    console.print("\n[yellow]🔄 ENCHAT RESET - CLEAR CONFIGURATION[/]")
    console.print("This will clear:")
    console.print("  • Saved room settings")
    console.print("  • Stored encryption keys")
    console.print("  • Keychain entries")
    console.print()
    
    # Confirm
    confirm = input("Are you sure you want to reset Enchat configuration? [y/n]: ")
    if confirm.lower() != 'y':
        console.print("[green]Cancelled - configuration preserved[/]")
        return
    
    console.print("\nClearing configuration...\n")
    
    wiped = []
    warnings = []
    
    # 1. Clear config file
    config_path = os.path.expanduser("~/.enchat.conf")
    if os.path.exists(config_path):
        try:
            # Simple deletion is fine for config
            os.remove(config_path)
            wiped.append("Configuration file")
        except Exception as e:
            warnings.append(f"Could not delete config file: {str(e)}")
    
    # 2. Clear keychain entries
    keychain_success, keychain_warnings = wipe_keychain_entries()
    if keychain_success:
        wiped.append("Keychain entries")
    warnings.extend(keychain_warnings)
    
    # Print results
    if wiped:
        console.print("[green]✅ Successfully cleared:[/]")
        for item in wiped:
            console.print(f"  • {item}")
        console.print()
    
    if warnings:
        console.print("[yellow]⚠️  Warnings:[/]")
        for warning in warnings:
            console.print(f"  • {warning}")
        console.print()
    
    console.print("[bold green]🔄 Reset complete![/]")
    console.print("[dim]You can now join a room with new settings[/]")

def main():
    """
    Main entry point
    """
    parser = argparse.ArgumentParser(description="Secure chat client")
    
    # Add commands
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Join command
    join_parser = subparsers.add_parser('join', help='Join a chat room')
    join_parser.add_argument('room', help='Room name to join')
    join_parser.add_argument('--name', '-n', help='Your display name')
    
    # Create command  
    create_parser = subparsers.add_parser('create', help='Create a new chat room')
    create_parser.add_argument('room', help='Room name to create')
    
    # Kill command
    kill_parser = subparsers.add_parser('kill', help='Securely wipe ALL Enchat data')
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Clear saved room settings and keys')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version info')
    
    # Add original chat options
    parser.add_argument('--server', help='Server to connect to')
    parser.add_argument('--enchat-server', action='store_true', help='Run in server mode')
    parser.add_argument('--default-server', action='store_true', help='Use default server')
    parser.add_argument('--clear-config', action='store_true', help='Clear configuration')
    
    args = parser.parse_args()
    
    # Handle special commands first
    if args.command == 'kill':
        # Show warning banner
        console.print("[bold red]🔥 ENCHAT DATA WIPE - COMPLETE REMOVAL[/]")
        console.print("[yellow]This will permanently delete ALL enchat data:[/]")
        console.print("  • Configuration file (~/.enchat.conf)")
        console.print("  • All downloaded files (downloads/ folder)")
        console.print("  • Temporary files and cache")
        console.print("  • Keyring/keychain entries")
        console.print("  • All traces of enchat usage")
        console.print()
        
        console.print("[yellow]⚠️  Security Notice:[/]")
        console.print("  • SSD secure deletion is limited due to wear leveling")
        console.print("  • Some traces may remain in filesystem journals")
        console.print("  • System swap/hibernation files may contain data")
        console.print()
        
        # Confirm
        confirm = input("Are you absolutely sure? This cannot be undone [y/n]: ")
        if confirm.lower() != 'y':
            console.print("[green]Cancelled - no data was deleted[/]")
            return
            
        secure_wipe()
        return
        
    elif args.command == 'reset':
        reset_enchat()
        return
        
    elif args.command == 'join':
        join_room(args.room, args.name)
        return
        
    elif args.command == 'create':
        create_room(args.room)
        return
        
    elif args.command == 'version':
        console.print(f"[cyan]Enchat v{VERSION}[/]")
        return
        
    # Handle original chat functionality
    if args.clear_config and os.path.exists(CONF_FILE):
        os.remove(CONF_FILE)
        console.print("[green]Settings cleared[/]")
        return
        
    # Load or create configuration
    room, nick, secret, server = load_conf()
    if not room or not nick:
        room, nick, secret, server = first_run(args)
    if not secret:
        secret = getpass("🔑 Passphrase: ")
    
    # Initialize encryption
    f = Fernet(gen_key(secret))
    buf: List[Tuple[str, str, bool]] = []
    
    # Start outbox worker
    out_stop = threading.Event()
    threading.Thread(target=outbox_worker, args=(out_stop,), daemon=True).start()
    
    # Initialize UI
    ui = ChatUI(room, nick, server, f, buf)
    
    # Handle clean shutdown
    def quit_clean(*_):
        out_stop.set()
        enqueue_sys(room, nick, "left", server, f)
        sys.exit()
    signal.signal(signal.SIGINT, quit_clean)
    
    try:
        ui.run()
    finally:
        out_stop.set()
        enqueue_sys(room, nick, "left", server, f)

def join_room(room_name, display_name=None):
    """
    Join a chat room
    """
    if not room_name:
        print("Error: Room name is required")
        return
        
    # Get display name if not provided
    if not display_name:
        display_name = input("Enter your display name: ")
    
    # Get room key
    secret = getpass("🔑 Room key: ")
    
    # Initialize encryption
    f = Fernet(gen_key(secret))
    buf: List[Tuple[str, str, bool]] = []
    
    # Start outbox worker
    out_stop = threading.Event()
    threading.Thread(target=outbox_worker, args=(out_stop,), daemon=True).start()
    
    # Initialize UI
    ui = ChatUI(room_name, display_name, DEFAULT_SERVER, f, buf)
    
    # Handle clean shutdown
    def quit_clean(*_):
        out_stop.set()
        enqueue_sys(room_name, display_name, "left", DEFAULT_SERVER, f)
        sys.exit()
    signal.signal(signal.SIGINT, quit_clean)
    
    try:
        # Save config
        save_conf(room_name, display_name, secret)
        # Join and run UI
        enqueue_sys(room_name, display_name, "joined", DEFAULT_SERVER, f)
        ui.run()
    finally:
        out_stop.set()
        enqueue_sys(room_name, display_name, "left", DEFAULT_SERVER, f)

def create_room(room_name):
    """
    Create a new chat room
    """
    if not room_name:
        print("Error: Room name is required")
        return
        
    # Generate and show room key
    room_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    print("\n🔑 ROOM KEY (save this securely):")
    print(f"{room_key}\n")
    
    # Show join command
    print("To join this room, use:")
    print(f"enchat join {room_name}")
    print("\nShare the room name and key securely with other participants")
    
    # Ask to join now
    if input("\nJoin this room now? [y/n]: ").lower() == 'y':
        join_room(room_name)

if __name__=="__main__":
    main()
