#!/usr/bin/env python3
"""Auto-confirm emulator button prompts via the debug link.

Connects to the emulator's debug link (UDP base_port + 1) and automatically
presses YES whenever a layout is visible.  Designed to run as a background
process during headless integration tests.

Uses read_layout(wait=True) which returns the CURRENT layout (or waits for
one to appear).  This avoids the pitfall of wait_layout() which waits for
the NEXT layout *change* and blocks forever if a screen is already displayed.

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
            layout = debug.read_layout(wait=True)
            LOG.info("layout visible, pressing YES")
            debug.press_yes()
        except KeyboardInterrupt:
            break
        except Exception as exc:
            LOG.warning("auto-confirm error (retrying): %s", exc)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
