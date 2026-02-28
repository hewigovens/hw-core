#!/usr/bin/env python3
"""Auto-confirm emulator button prompts via the debug link.

Sends a fire-and-forget DebugLinkDecision(button=YES) every 2 seconds.
Only the decision message is sent — no DebugLinkGetState follow-up — to
avoid protocol desync when the firmware's debug handler returns a Failure
(e.g. no layout is visible yet).

An optional initial delay prevents pressing buttons before the pairing
dialog appears, which would otherwise navigate the homescreen/menus and
leave the emulator in an unexpected state.

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
    transport.begin_session()
    LOG.info(
        "auto-confirm ready on port %d (initial delay %ds)",
        debug_port,
        initial_delay,
    )

    if initial_delay > 0:
        time.sleep(initial_delay)

    LOG.info("auto-confirm now pressing YES every 2s")

    while True:
        try:
            # Fire-and-forget: send only DebugLinkDecision, don't read response.
            # This avoids desync from unexpected Failure responses when no layout
            # is visible (firmware's wait_until_layout_is_running raises after 3s).
            msg = messages.DebugLinkDecision(button=messages.DebugButton.YES)
            transport.write(msg)
        except KeyboardInterrupt:
            break
        except Exception:
            pass
        time.sleep(2)


if __name__ == "__main__":
    main()
