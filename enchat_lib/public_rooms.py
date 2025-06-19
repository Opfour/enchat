# This file defines the available public rooms for Enchat.
# The key is the room name the user will type.
# The value is a tuple containing:
# (The actual ntfy.sh topic, The hardcoded public passphrase)

# NOTE: The passphrase is public knowledge. The encryption here only
# prevents casual snooping on the public ntfy.sh server, it does not
# provide privacy from other Enchat users in the public room.

PUBLIC_ROOMS = {
    "lobby": (
        "enchat-public-lobby-v1",  # ntfy.sh topic
        "enchat_public_key_001"    # Publicly known passphrase
    ),
    "gaming": (
        "enchat-public-gaming-v1",
        "enchat_gaming_key_456"
    ),
    "lottery": (
        "enchat-public-lottery-v1",
        "enchat_lottery_key_789"
    )
} 