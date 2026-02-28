#!/usr/bin/env python3
"""Auto-confirm emulator button prompts via the debug link.

Sends a fire-and-forget DebugLinkDecision(button=YES) every 2 seconds
using DebugLink._write() (no DebugLinkGetState follow-up).  This avoids
protocol desync when the firmware returns Failure for presses with no
layout visible.

An optional initial delay prevents pressing buttons on the homescreen
before the BLE pairing dialog appears.

Usage:
    python3 auto-confirm.py <debug_port> [initial_delay_secs]
    # debug_port is typically 21325 (= 21324 + 1)
    # initial_delay_secs defaults to 0
"""

import sys
import time
import logging

from trezorlib import messages
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
    initial_delay = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    transport = UdpTransport(f"127.0.0.1:{debug_port}")
    debug = DebugLink(transport=transport, auto_interact=True)
    LOG.info(
        "auto-confirm ready on port %d (initial delay %ds)",
        debug_port,
        initial_delay,
    )

    if initial_delay > 0:
        time.sleep(initial_delay)

    LOG.info("auto-confirm now pressing YES every 2s")

    decision = messages.DebugLinkDecision(button=messages.DebugButton.YES)
    while True:
        try:
            # Fire-and-forget: _write sends the decision via protocol_v1
            # without reading a response or sending DebugLinkGetState.
            debug._write(decision)
        except KeyboardInterrupt:
            break
        except Exception:
            pass
        time.sleep(2)


if __name__ == "__main__":
    main()
