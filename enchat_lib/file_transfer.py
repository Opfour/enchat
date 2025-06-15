import os
import hashlib
import uuid
import json

from . import state, constants, notifications, crypto, session_key
from .state import outbox_queue

def ensure_file_dir():
    """Ensure secure temporary directory exists"""
    os.makedirs(constants.FILE_TEMP_DIR, mode=0o700, exist_ok=True)

def ensure_downloads_dir():
    """Ensure downloads directory exists in project folder"""
    os.makedirs(constants.DOWNLOADS_DIR, exist_ok=True)

def sanitize_filename(filename, fallback_id="unknown"):
    """
    Sanitize filename to prevent directory traversal and other security issues.
    Returns a safe filename suitable for use in downloads directory.
    """
    if not filename:
        return f"file_{fallback_id}"
    
    safe_name = os.path.basename(filename)
    
    if not safe_name or safe_name in ('.', '..') or safe_name.startswith('.'):
        return f"file_{fallback_id}"
    
    import re
    safe_name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', safe_name)
    
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:255-len(ext)] + ext
    
    return safe_name if safe_name else f"file_{fallback_id}"

def split_file_to_chunks(filepath, f_cipher):
    """Split file into encrypted chunks for transfer"""
    if not os.path.exists(filepath):
        return None, "File not found"
    
    file_size = os.path.getsize(filepath)
    if file_size > constants.MAX_FILE_SIZE:
        return None, f"File too large (max {constants.MAX_FILE_SIZE // (1024*1024)}MB)"
    
    file_id = str(uuid.uuid4())[:8]
    filename = os.path.basename(filepath)
    file_hash = hashlib.sha256()
    chunks = []
    
    try:
        with open(filepath, 'rb') as f:
            chunk_num = 0
            while True:
                chunk_data = f.read(constants.CHUNK_SIZE)
                if not chunk_data:
                    break
                
                file_hash.update(chunk_data)
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
    
    is_complete = (total_chunks == 0)
    
    state.available_files[file_id] = {
        'metadata': metadata,
        'sender': sender,
        'chunks_received': 0,
        'total_chunks': total_chunks,
        'complete': is_complete
    }
    state.file_chunks[file_id] = {}
    
    size_mb = size / (1024 * 1024)
    buf.append(("System", f"📎 {sender} shared: {filename} ({size_mb:.1f}MB, {total_chunks} chunks)", False))
    
    if is_complete:
        buf.append(("System", f"✅ {filename} ready! Use '/download {file_id}' (empty file)", False))
    else:
        buf.append(("System", f"   File ID: {file_id} - Use '/download {file_id}' when complete", False))
    
    notifications.notify(f"{sender} shared file: {filename}")

def handle_file_chunk(chunk_data, sender, buf):
    """Handle incoming file chunk"""
    file_id = chunk_data['file_id']
    chunk_num = chunk_data['chunk_num']
    
    if file_id in state.available_files:
        state.file_chunks[file_id][chunk_num] = chunk_data
        state.available_files[file_id]['chunks_received'] = len(state.file_chunks[file_id])
        
        received = state.available_files[file_id]['chunks_received']
        total = state.available_files[file_id]['total_chunks']
        filename = state.available_files[file_id]['metadata']['filename']
        
        if received % max(1, total // 10) == 0 or received == total:
            progress = int((received / total) * 100)
            buf.append(("System", f"📥 {filename}: {progress}% ({received}/{total})", False))
        
        if received == total:
            state.available_files[file_id]['complete'] = True
            buf.append(("System", f"✅ {filename} ready! Use '/download {file_id}'", False))

def assemble_file_from_chunks(file_id, f_cipher):
    """Assemble file from chunks and save to temp directory"""
    if file_id not in state.available_files or not state.available_files[file_id]['complete']:
        return None, "File not available or incomplete"
    
    ensure_file_dir()
    metadata = state.available_files[file_id]['metadata']
    chunks_dict = state.file_chunks[file_id]
    
    try:
        temp_path = os.path.join(constants.FILE_TEMP_DIR, f"{file_id}_{metadata['filename']}")
        file_hash = hashlib.sha256()
        
        if metadata['total_chunks'] == 0:
            with open(temp_path, 'wb') as f:
                pass
            file_hash.update(b'')
        else:
            sorted_chunks = [chunks_dict[i] for i in sorted(chunks_dict.keys())]
            
            with open(temp_path, 'wb') as f:
                for chunk in sorted_chunks:
                    decrypted_data = f_cipher.decrypt(chunk['data'].encode())
                    file_hash.update(decrypted_data)
                    f.write(decrypted_data)
        
        if file_hash.hexdigest() != metadata['hash']:
            os.remove(temp_path)
            return None, "File integrity check failed"
        
        return temp_path, None
    except Exception as e:
        return None, f"Error assembling file: {e}"

def enqueue_file_chunk(room, nick, chunk_data, server, f):
    """Send a file chunk"""
    chunk_json = json.dumps(chunk_data)
    outbox_queue.put(("FILECHUNK", room, nick, chunk_json, server, f))

def enqueue_file_meta(room, nick, metadata, server, f):
    """Send file metadata"""
    meta_json = json.dumps(metadata)
    outbox_queue.put(("FILEMETA", room, nick, meta_json, server, f))
