import threading
import time
import queue
import shutil

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

from . import state, constants, network, commands
from .utils import trim
from .input import start_char_thread

class ChatUI:
    def __init__(self, room, nick, server, f, buf, is_public=False, is_tor=False):
        self.room, self.nick, self.server, self.f = room, nick, server, f
        self.buf = buf
        self.is_public = is_public
        self.is_tor = is_tor
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="input", size=3),
        )
        self.redraw = True
        self.last_len = len(buf)
        self.last_input = ""
        self.last_terminal_size = (0, 0)

    def _head(self):
        parts = [
            (" ENCHAT ", "bold cyan"),
            (" CONNECTED ", "bold green"),
            (f" {self.room} ", "white"),
        ]
        if self.is_tor:
            parts.append(("🧅 TOR ", "bold purple"))
        
        parts.extend([
            (f" {self.nick} ", "magenta"),
            (" | " + self.server.replace("https://", ""), "dim")
        ])
        
        return Panel(Text.assemble(*parts), style="blue")

    def _body(self):
        try:
            terminal_height = shutil.get_terminal_size().lines
            available_lines = max(3, terminal_height - 10)
        except Exception:
            available_lines = 20
        
        messages_to_show = self.buf[-available_lines:]
        
        t = Text()
        for msg in messages_to_show:
            # Safely unpack the message tuple
            sender, content, own = msg[0], msg[1], msg[2]
            is_mention = msg[3] if len(msg) > 3 else False

            if sender == "System":
                system_line = Text("[SYSTEM] ", style="yellow")
                if isinstance(content, Text):
                    system_line.append(content)
                else:
                    system_line.append(Text.from_markup(str(content)))
                system_line.append("\n")
                t.append(system_line)
            else:
                lab, st = ("You", "green") if own else (sender, "cyan")
                
                if is_mention:
                    # Style the entire line for high visibility and readability
                    t.append(f"{lab}: {content}\n", style="black on yellow")
                else:
                    # Use the original, unchanged message style
                    t.append(f"{lab}: ", style=st)
                    t.append(f"{content}\n")
                
        return Panel(t, title=f"Messages ({len(self.buf)})", padding=(0, 1))

    def _inp(self):
        entered = "".join(state.current_input)
        txt = Text(f"{self.nick}: ", style="bold green")
        txt.append(entered or "…", style="white")
        txt.append(f"  {len(entered)}/{constants.MAX_MSG_LEN}", style="dim")
        return Panel(Align.left(txt), title="Type message", padding=(0, 1))

    def run(self):
        stop_evt = threading.Event()
        threading.Thread(target=network.listener, args=(self.room, self.nick, self.f, self.server, self.buf, stop_evt), daemon=True).start()
        start_char_thread()

        self.buf.append(("System", f"Joined '{self.room}'", False))
        network.enqueue_sys(self.room, self.nick, "joined", self.server, self.f)

        def pinger():
            while not stop_evt.is_set():
                network.enqueue_sys(self.room, self.nick, "ping", self.server, self.f)
                time.sleep(constants.PING_INTERVAL)
        threading.Thread(target=pinger, daemon=True).start()

        with Live(self.layout, refresh_per_second=10, screen=False) as live:
            while True:
                if len(self.buf) != self.last_len or "".join(state.current_input) != self.last_input:
                    self.redraw = True
                    self.last_len = len(self.buf)
                    self.last_input = "".join(state.current_input)

                try:
                    current_size = shutil.get_terminal_size()
                    if (current_size.lines, current_size.columns) != self.last_terminal_size:
                        self.last_terminal_size = (current_size.lines, current_size.columns)
                        self.redraw = True
                except:
                    pass

                if self.redraw:
                    self.layout["header"].update(self._head())
                    self.layout["body"].update(self._body())
                    self.layout["input"].update(self._inp())
                    live.refresh()
                    self.redraw = False

                try:
                    line = state.input_queue.get_nowait()
                except queue.Empty:
                    time.sleep(0.05)
                    continue

                self.redraw = True
                if not line:
                    continue
                
                if line.startswith("/"):
                    if commands.handle_command(line, self.room, self.nick, self.server, self.f, self.buf, self.is_public, self.is_tor) == "exit":
                        break
                else:
                    if len(line) > constants.MAX_MSG_LEN:
                        self.buf.append(("System", "❌ Message too long", False, False))
                        continue
                    network.enqueue_msg(self.room, self.nick, line, self.server, self.f)
                    self.buf.append((self.nick, line, True, False))
                    trim(self.buf)

        # The loop has exited, so we just need to stop the listener thread.
        # The main script (enchat.py) will handle sending the "left" message.
        stop_evt.set()
