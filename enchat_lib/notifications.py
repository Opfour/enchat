import sys
import subprocess
from shutil import which
from . import state

def notify(msg: str):
    """Sends a desktop notification if notifications are enabled."""
    if not state.notifications_enabled:
        return
    
    if sys.platform.startswith("linux") and which("notify-send"):
        subprocess.run(["notify-send", "Enchat", msg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "darwin" and which("osascript"):
        subprocess.run(["osascript", "-e", f'display notification "{msg}" with title "Enchat"'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "win32":
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception:
            pass
