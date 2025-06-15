#!/usr/bin/env python3
"""enchat – encrypted terminal chat
Route B • 2025-06-15
"""
import argparse
import base64
import os
import signal
import sys
import threading
from getpass import getpass
from typing import List, Tuple

from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt

# Local modules from enchat_lib
from enchat_lib import (
    config, constants, crypto, network, secure_wipe, ui
)
from enchat_lib.constants import VERSION, KEYRING_AVAILABLE

console = Console()

def first_run(args):
    """Guides the user through the first-time setup."""
    console.clear()
    console.print("[bold cyan]🔐 First-time setup[/]")
    room = Prompt.ask("🏠 Room").strip().lower()
    nick = Prompt.ask("👤 Nick").strip()
    secret = getpass("🔑 Passphrase: ")
    
    server_url = getattr(args, 'server', None)
    if server_url:
        server = server_url.rstrip('/')
    else:
        console.print("[cyan]Server: 1) enchat (recommended)  2) ntfy.sh (public)  3) custom[/]")
        choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="1")
        server = constants.ENCHAT_NTFY if choice == "1" else constants.DEFAULT_NTFY if choice == "2" else Prompt.ask("URL").rstrip('/')

    if KEYRING_AVAILABLE and Prompt.ask("Save passphrase in keychain?", choices=["y", "n"], default="y") == "y":
        config.save_passphrase_keychain(room, secret)
        config.save_conf(room, nick, "", server)
    else:
        config.save_conf(room, nick, secret, server)
        
    return room, nick, secret, server

def start_chat(room: str, nick: str, secret: str, server: str, buf: List[Tuple[str, str, bool]]):
    """Initializes and runs the chat UI."""
    if not secret:
        secret = getpass(f"🔑 Passphrase for room '{room}': ")

    f = Fernet(crypto.gen_key(secret))
    
    out_stop = threading.Event()
    threading.Thread(target=network.outbox_worker, args=(out_stop,), daemon=True).start()

    chat_ui = ui.ChatUI(room, nick, server, f, buf)
    
    def quit_clean(*_):
        out_stop.set()
        console.print("\n[yellow]Exiting...[/]")
        sys.exit(0)

    signal.signal(signal.SIGINT, quit_clean)
    signal.signal(signal.SIGTERM, quit_clean)
    
    try:
        chat_ui.run()
    finally:
        out_stop.set()

def join_room(args):
    """Handler for the 'join' command."""
    room_name = args.room
    display_name = args.name or Prompt.ask("👤 Nick").strip()
    secret = getpass("🔑 Room key: ")
    server = args.server or constants.DEFAULT_NTFY
    
    config.save_conf(room_name, display_name, secret, server)
    if KEYRING_AVAILABLE and Prompt.ask("Save passphrase in keychain?", choices=["y","n"], default="y")=="y":
        config.save_passphrase_keychain(room_name, secret)

    console.print(f"[green]Joining room '{room_name}' as '{display_name}'...[/]")
    start_chat(room_name, display_name, secret, server, [])


def create_room(args):
    """Handler for the 'create' command."""
    room_name = args.room
    room_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    console.print("\n[bold green]🔑 New Room Key (save this securely!):[/]")
    console.print(f"[yellow]{room_key}[/]")
    console.print(f"\nTo join, others can run:\n[cyan]python3 enchat.py join {room_name}[/]\n")
    
    if Prompt.ask("Join this room now?", choices=["y", "n"], default="y") == 'y':
        display_name = Prompt.ask("👤 Nick").strip()
        server = args.server or constants.DEFAULT_NTFY
        config.save_conf(room_name, display_name, room_key, server)
        start_chat(room_name, display_name, room_key, server, [])

def main():
    """Main entry point: parses arguments and starts the correct action."""
    parser = argparse.ArgumentParser(
        description="enchat – encrypted terminal chat.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('--server', help='Custom ntfy server URL to override saved/default.')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Default command (run with existing config)
    run_parser = subparsers.add_parser('run', help='Run Enchat with saved settings (default action)')

    # Join command
    join_parser = subparsers.add_parser('join', help='Join a new or existing chat room.')
    join_parser.add_argument('room', help='Room name to join.')
    join_parser.add_argument('--name', '-n', help='Your display name.')

    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new chat room and key.')
    create_parser.add_argument('room', help='Name of the room to create.')

    # Maintenance commands
    reset_parser = subparsers.add_parser('reset', help='Clear saved room settings and keys.')
    kill_parser = subparsers.add_parser('kill', help='Securely wipe ALL Enchat data.')
    version_parser = subparsers.add_parser('version', help='Show version info.')

    # If no command is given, default to 'run'
    args = parser.parse_args(sys.argv[1:] if sys.argv[1:] else ['run'])
    
    if args.command == 'version':
        console.print(f"[cyan]Enchat v{VERSION}[/]")
        return
        
    if args.command == 'kill':
        console.print("[bold red]🔥 ENCHAT DATA WIPE - COMPLETE REMOVAL[/]")
        if Prompt.ask("Are you absolutely sure?", choices=["y", "n"], default="n") == 'y':
            secure_wipe.secure_wipe()
        else:
            console.print("[green]Cancelled.[/]")
        return
        
    if args.command == 'reset':
        secure_wipe.reset_enchat()
        return

    if args.command == 'join':
        join_room(args)
        return
    
    if args.command == 'create':
        create_room(args)
        return
        
    # Default action: run with config or do first-time setup
    room, nick, secret, server_conf = config.load_conf()
    server = args.server or server_conf
    
    if not all((room, nick, server)):
        room, nick, secret, server = first_run(args)

    start_chat(room, nick, secret, server, [])

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Exited gracefully.[/]")
        sys.exit(0) 