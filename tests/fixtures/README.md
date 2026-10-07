# Test Fixtures

## bluez-emu-bridge

Vendored from [trezor-firmware](https://github.com/trezor/trezor-firmware) at commit `cfec1811b739a6c45255cffe490c062e3a05ae76`.

Source files:
- `core/tools/bluez-emu-bridge.py`
- `core/tools/bluez_emu_bridge/`

`bluez-emu-bridge.py` carries local patches: the push characteristic (`8c000004`),
`_data_transport` naming, MAC formatting, a retained scan task, and padding of
host writes to 244 bytes (firmware core v2.12+ rejects short BLE packets).

## tropic_model

`tropic_model/config.yml` is vendored from trezor-firmware `tests/tropic_model/config.yml`
at `core/v2.12.5` (`66ac7295aaa0aa9fb427a0cc035b34dd61b6d472`). It configures the
TROPIC01 model (`model_server` from [ts-tvl](https://github.com/tropicsquare/ts-tvl))
that the emulator requires since core v2.12.

## trezor-emu-core-T3W1

Not committed — downloaded in CI from the `emu-fixtures-v2.12.5` GitHub release
(built from trezor-firmware `core/v2.12.5`). Build instructions in CONTRIBUTING.md.
