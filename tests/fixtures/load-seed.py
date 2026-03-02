#!/usr/bin/env python3
"""Load SLIP-14 seed onto a fresh Trezor emulator via debuglink.

Called by the test harness after starting the emulator.
Requires: pip install trezor
"""
import sys

from trezorlib.debuglink import TrezorTestContext, load_device
from trezorlib.transport.udp import UdpTransport

port = int(sys.argv[1]) if len(sys.argv) > 1 else 21324
transport = UdpTransport(f"127.0.0.1:{port}")
ctx = TrezorTestContext(transport, auto_interact=True)

mnemonic = " ".join(["all"] * 12)
load_device(
    ctx.get_session(passphrase=None),
    mnemonic,
    pin=None,
    passphrase_protection=False,
    label="SLIP-0014",
)

print("Device loaded with SLIP-14 seed", file=sys.stderr)
