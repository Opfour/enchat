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
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

# Local modules from enchat_lib
from enchat_lib import (
    config, constants, crypto, network, secure_wipe, ui
)
from enchat_lib.constants import VERSION, KEYRING_AVAILABLE

console = Console()

def _render_header(title: str):
    """Renders a standardized header panel."""
    console.clear()
    header_text = Text("enchat", style="bold cyan", justify="center")
    panel = Panel(
        header_text,
        title=f"v{VERSION}",
        subtitle=f"[bold blue]{title}[/]",
        border_style="blue"
    )
    console.print(panel)
    console.print()

def first_run(args):
    """Guides the user through the first-time setup with an enhanced UI."""
    _render_header("First-Time Setup")
    
    console.print(Panel(
        Text.from_markup(
            "Welcome to [bold cyan]enchat[/]! Let's get you set up.\n\n"
            "A [bold]Room[/] is a shared chat space.\n"
            "A [bold]Passphrase[/] is the key to that room. [bold red]Never lose it![/]"
        ),
        title="Welcome",
        border_style="green",
        padding=(1, 2)
    ))
    
    room = Prompt.ask("🏠 Room Name")
    nick = Prompt.ask("👤 Nickname")
    secret = getpass("🔑 Passphrase (will be hidden)")
    
    server_url = getattr(args, 'server', None)
    if server_url:
        server = server_url.rstrip('/')
        console.print(f"🌍 Using custom server: [bold cyan]{server}[/]")
    else:
        console.print("📡 Please choose a server:")
        choice = Prompt.ask(
            Text.from_markup(
                "   [bold]1)[/] [green]Enchat Server[/] (Recommended, private)\n"
                "   [bold]2)[/] [yellow]Public ntfy.sh[/] (Functional, less private)\n"
                "   [bold]3)[/] [cyan]Custom Server[/]"
            ),
            choices=["1", "2", "3"],
            default="1"
        )
        server = constants.ENCHAT_NTFY if choice == "1" else constants.DEFAULT_NTFY if choice == "2" else Prompt.ask("Enter Custom Server URL").rstrip('/')

    if Prompt.ask("\n💾 Save these settings for next time?", choices=["y", "n"], default="y") == "y":
        if KEYRING_AVAILABLE and Prompt.ask("🔐 Save passphrase securely in system keychain?", choices=["y", "n"], default="y") == "y":
            config.save_passphrase_keychain(room, secret)
        config.save_conf(room, nick, "", server)
        console.print("[green]Settings saved.[/]")
        
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
    """Handler for the 'join' command with an enhanced UI."""
    _render_header("Join Room")
    room_name = args.room or Prompt.ask("🏠 Room Name to join")
    display_name = args.name or Prompt.ask("👤 Your Nickname")
    secret = getpass("🔑 Room Passphrase (will be hidden)")
    server = args.server or constants.DEFAULT_NTFY
    
    if Prompt.ask("\n💾 Save these room settings for next time?", choices=["y", "n"], default="n") == 'y':
        if KEYRING_AVAILABLE and Prompt.ask("🔐 Save passphrase securely in system keychain?", choices=["y","n"], default="y")=="y":
            config.save_passphrase_keychain(room_name, secret)
        config.save_conf(room_name, display_name, "", server)
        console.print("[green]Settings saved.[/]")

    console.print(f"\n[green]Joining room '{room_name}' as '{display_name}'...[/]")
    start_chat(room_name, display_name, secret, server, [])


def create_room(args):
    """Handler for the 'create' command with an enhanced UI."""
    _render_header("Create New Room")
    room_name = args.room or Prompt.ask("🏠 New Room Name")
    room_key = base64.urlsafe_b64encode(os.urandom(32)).decode()

    key_panel = Panel(
        Text(room_key, justify="center", style="bold yellow"),
        title="🔑 Your New Room Key",
        border_style="red",
        subtitle="[dim]Share this with other participants[/]"
    )
    console.print(key_panel)
    console.print(Text.from_markup("[bold red]Warning:[/b red] You cannot recover this key. Store it securely!"))
    
    if Prompt.ask("\n🤝 Join this room now?", choices=["y", "n"], default="y") == 'y':
        display_name = Prompt.ask("👤 Your Nickname")
        server = args.server or constants.DEFAULT_NTFY
        
        if Prompt.ask("💾 Save these room settings for next time?", choices=["y", "n"], default="n") == 'y':
            if KEYRING_AVAILABLE and Prompt.ask("🔐 Save new room key in system keychain?", choices=["y","n"], default="y") == 'y':
                config.save_passphrase_keychain(room_name, room_key)
            config.save_conf(room_name, display_name, "", server)
            console.print("[green]Settings saved.[/]")

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