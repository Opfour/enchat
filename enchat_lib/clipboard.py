"""
Cross-platform clipboard utility.
"""

def copy_to_clipboard(text: str) -> bool:
    """
    Copies the given text to the system clipboard.
    """
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except (ImportError, pyperclip.PyperclipException):
        return False 