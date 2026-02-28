#!/usr/bin/env python3
"""Auto-confirm emulator button prompts via the debug link.

Sends a raw DebugLinkDecision(button=YES) to the emulator's debug port
once per second.  The firmware processes the button press without sending
a response (fire-and-forget), so this script never blocks on reads and
never starves the emulator's cooperative event loop.

If no layout is currently displayed the firmware ignores the decision
(wait_until_layout_is_running waits briefly then times out).

Usage:
    python3 auto-confirm.py <debug_port>
    # debug_port is typically 21325 (= 21324 + 1)
"""

import socket
import struct
import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.StreamHandler()],
)
LOG = logging.getLogger("auto-confirm")

# Wire protocol v1 constants
HEADER_MAGIC = 0x3F  # '?'
MSG_TYPE_DEBUG_LINK_DECISION = 100
CHUNK_SIZE = 64

# Protobuf encoding of DebugLinkDecision(button=YES)
# field 6 (button), wire type 0 (varint): tag = (6 << 3) | 0 = 48 = 0x30
# DebugButton.YES = 1
DECISION_PAYLOAD = b"\x30\x01"


def make_chunk(msg_type: int, payload: bytes) -> bytes:
    """Build a single wire-protocol-v1 chunk (64 bytes)."""
    header = struct.pack(">BHI", HEADER_MAGIC, msg_type, len(payload))
    return (header + payload).ljust(CHUNK_SIZE, b"\x00")


def main() -> None:
    debug_port = int(sys.argv[1]) if len(sys.argv) > 1 else 21325
    addr = ("127.0.0.1", debug_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(addr)

    chunk = make_chunk(MSG_TYPE_DEBUG_LINK_DECISION, DECISION_PAYLOAD)

    LOG.info("auto-confirm ready on port %d", debug_port)

    while True:
        try:
            sock.send(chunk)
            time.sleep(1.0)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            LOG.warning("auto-confirm error (retrying): %s", exc)
            time.sleep(1.0)


if __name__ == "__main__":
    main()
