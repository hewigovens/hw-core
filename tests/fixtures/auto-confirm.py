#!/usr/bin/env python3
"""Auto-confirm emulator button prompts via the debug link.

Calls press_yes(wait=False) every 0.5 seconds.  The `wait=False` flag
uses IMMEDIATE ack mode so each call completes quickly (no blocking
wait for the next layout).  The 0.5 s sleep prevents flooding the
emulator's cooperative event loop.

Usage:
    python3 auto-confirm.py <debug_port>
    # debug_port is typically 21325 (= 21324 + 1)
"""

import sys
import time
import logging

from trezorlib.transport.udp import UdpTransport
from trezorlib.debuglink import DebugLink

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.StreamHandler()],
)
LOG = logging.getLogger("auto-confirm")


def main() -> None:
    debug_port = int(sys.argv[1]) if len(sys.argv) > 1 else 21325
    transport = UdpTransport(f"127.0.0.1:{debug_port}")
    debug = DebugLink(transport=transport, auto_interact=True)
    LOG.info("auto-confirm ready on port %d", debug_port)

    while True:
        try:
            debug.press_yes(wait=False)
        except KeyboardInterrupt:
            break
        except Exception:
            pass
        time.sleep(0.5)


if __name__ == "__main__":
    main()
