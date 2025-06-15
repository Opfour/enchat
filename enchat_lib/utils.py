from . import constants

def trim(buf: list):
    """Trims a buffer to a maximum size."""
    if len(buf) > constants.BUFFER_LIMIT:
        del buf[:constants.TRIM_STEP]
