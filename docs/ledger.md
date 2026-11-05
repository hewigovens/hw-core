# Direct Ledger BLE support

The experimental `ledger-connect` crate talks directly to a Ledger over Bluetooth through
`btleplug`. It does not use Ledger Live, a browser bridge, or a Ledger backend service.
The initial hardware target is **Stax**. Nano X and Flex profiles are also provided, but
profiles alone do not establish tested hardware support. Nano S/S Plus USB support is
outside this implementation.

## CLI

Enable Bluetooth on the Ledger, unlock it, and close other apps that are using its BLE
connection. Accept any OS/device Bluetooth pairing prompt. Open the Ethereum, Solana, or Bitcoin app before
requesting an address or signature for that chain; `connect` can inspect the currently running app.

```sh
cargo run -p hw-cli -- ledger --model stax scan
cargo run -p hw-cli -- ledger --model stax connect
cargo run -p hw-cli -- ledger --model stax address
cargo run -p hw-cli -- ledger --model stax sign-message --message 'Hello from hw-core'
```

Stax is the default model. Use `--model nano-x` or `--model flex` for those profiles.
If several devices are found, supply `--device-id` with the exact ID returned by `scan`.
Options such as `--model`, `--device-id`, `--scan-secs`, and `--timeout-secs` go before
the operation. The default scan lasts five seconds; the operation timeout is 120 seconds.
Addresses are displayed on the Ledger by default; `address --no-display` disables that
confirmation. Ethereum address display uses chain ID 1 unless `--chain-id` is provided.

`sign-transaction --tx @transaction.json` accepts the same EIP-1559 JSON fields as the
Trezor CLI. Quantities are hexadecimal strings; `chain_id` is an integer. For example:

```json
{
  "to": "0x000000000000000000000000000000000000dead",
  "value": "0x0",
  "nonce": "0x0",
  "gas_limit": "0x5208",
  "chain_id": 11155111,
  "max_fee_per_gas": "0x3b9aca00",
  "max_priority_fee": "0x3b9aca00",
  "data": "0x"
}
```

The shared wallet layer fetches the requested account, recovers the signer from the returned
signature, and rejects signatures that do not match that account. Transaction signing returns
normalized `v` (y-parity), `r`, `s`, the signing hash, the signed transaction bytes, and the
transaction hash (Keccak of the signed envelope). It never broadcasts. The caller owns nonce,
fee selection, and broadcasting. Trezor-specific display definitions are rejected.

`sign-message --message 'Hello from hw-core'` signs the UTF-8 bytes with the EIP-191 personal
message prefix. It verifies the recovered address and returns a standard 65-byte `r || s || v`
signature with `v` equal to 27 or 28, plus the message signing hash. This is not EIP-712 typed
data or raw-digest signing.

### Solana and EIP-712

```sh
cargo run -p hw-cli -- ledger solana-address
cargo run -p hw-cli -- ledger sign-solana-transaction --tx @message.hex
cargo run -p hw-cli -- ledger sign-solana-message --message 'Hello from hw-core'
cargo run -p hw-cli -- ledger sign-typed-data --data @typed-data.json
```

Solana uses `m/44'/501'/0'/0'` by default. Transaction input is the hex-encoded serialized
Solana **message** (legacy or v0), without a transaction signature wrapper. The returned
64-byte Ed25519 signature is verified against the requested public key and exact message.
Off-chain text signing constructs the OCMS v1 envelope used by Trezor, with sorted unique
signers, and returns that envelope as `signed_data` alongside the verified signature.
The default signer is the requested account. Requests must contain nonempty UTF-8 text.

EIP-712 JSON includes `types`, `primaryType`, `domain`, and `message`. Full JSON streams
struct definitions and values to the Ethereum app for field review; it never silently falls
back to hash signing. On Stax with Ethereum 1.13.0, enable **Raw messages** in the Ethereum
app settings to review unfiltered fields while leaving blind signing disabled. Without it,
the device can show “This transaction cannot be clear signed” and return `0x6a80` at domain
review. The host independently computes the EIP-712 digest and verifies the returned signer.
Explicit hash signing is available with both
`--domain-separator-hash HEX --message-hash HEX` instead of `--data`.

Full JSON supports nested structs, arrays, signed/unsigned integers, addresses, booleans,
strings, and bytes. Ledger protocol bounds include at most 255 array entries, 65,535 bytes
per scalar, and 255 bytes per encoded field definition. This implementation also bounds
nesting and command count. Domain-only signing, non-v4 mode, Trezor display definitions,
and ERC-7730/filtered clear-signing metadata are unsupported and rejected. Contracts and token transfers may require additional metadata or device
settings; generic APDU support does not establish validated clear-signing coverage.

### Bitcoin

```sh
cargo run -p hw-cli -- ledger bitcoin-address
cargo run -p hw-cli -- ledger sign-bitcoin-message --message 'Hello from hw-core'
cargo run -p hw-cli -- ledger sign-bitcoin-transaction --tx @bitcoin.json
```

The default path is `m/84'/0'/0'/0/0`. Addresses support standard BIP44, BIP49,
BIP84, and BIP86 single-key accounts. Coin type `1'` selects testnet and requires
**Bitcoin Test** on the device. The account xpub derives the expected address locally;
a mismatched device address is rejected.

Message signing supports BIP44/49/84 and returns a verified BIP137 compact signature
(base64 in the CLI and shared API). Taproot messages are rejected. The shared API also
accepts hex-encoded message bytes; the CLI accepts UTF-8 text.

Transaction signing accepts the existing Bitcoin JSON (`inputs`, `outputs`, `ref_txs`),
converts it to a PSBT, and uses Ledger's official Rust wallet-policy client over the
same direct BLE transport. This first pass supports **single-account BIP84 P2WPKH
inputs**, external address outputs, and internal `/1/index` P2WPKH change. Every input
requires a complete matching reference transaction. The host verifies its txid, prevout,
amount, and derived script, rejects duplicate inputs or outputs exceeding inputs, and
verifies each SIGHASH_ALL signature before returning it. The CLI and Rust result also
include the serialized signed transaction and txid; the shared FFI result retains the
existing per-input DER signature contract, without a sighash byte.

Multisig, mixed accounts, legacy/nested SegWit/Taproot inputs, OP_RETURN, Trezor replacement
and payment-request metadata are explicitly rejected. No transaction is broadcast.
`LedgerSessionHandle.sign_bitcoin_tx` and `WalletSession.signBitcoinTx` accept the
existing typed Bitcoin request. The sample JSON editor routes BTC to the selected vendor;
the built-in seeded-wallet fixture must be replaced with data for your Ledger account.

On 2026-11-05, Stax with **Bitcoin 2.5.1** passed BIP84 address confirmation,
message signing, and a single-input P2WPKH self-transfer signing test over BLE.
The transaction used a fabricated previous transaction, with a 9,000-sat output and
1,000-sat fee, and was never broadcast. The SDK and an independent Node/OpenSSL verifier
checked both signatures; the latter also reconstructed the txid and rejected a modified
message and prevout amount. This validates the CLI/device path, not sample-app signing
on hardware, testnet, other account purposes, or multisig/Taproot transactions.

## Rust and Swift/Kotlin

Rust consumers can use `hw_core::ledger` (or `ledger-connect` directly):

1. Scan with `BleManager::scan_profile(LedgerModel::Stax.profile(), duration)`.
2. Connect the chosen device using the same profile.
3. Construct `LedgerBleTransport::new(session, timeout)` and `LedgerClient::new(transport)`.
4. Call `app_info` or `ethereum_address`. Import `hw_core::wallet::ledger::LedgerEthereumExt`
   to use `sign_eip1559(&EthSignTx)` and `sign_verified_message(path, bytes)` for verified signing.
   `LedgerSolanaExt`, `LedgerTypedDataExt`, and `LedgerBitcoinExt` provide verified Solana, EIP-712, and Bitcoin operations.
5. Call `client.into_transport().disconnect().await` when finished.

The UniFFI surface provides `BleManagerHandle.discover_ledger`,
`LedgerDiscoveredDevice.connect`, and a separate `LedgerSessionHandle` with the same
operations and `disconnect`. Its `sign_eip1559` accepts the existing `SignTxRequest` record
with `chain = Ethereum`; `sign_personal_message` accepts raw message bytes. Both return
`LedgerSigningResult`. The low-level `sign_transaction` method still accepts caller-encoded
bytes and returns an unverified raw signature; prefer `sign_eip1559`. This avoids routing Ledger devices through THP bootstrap.
Existing Trezor workflow APIs are preserved. Custom `BleProfile` struct literals now
need `connection_probe` and `write_with_response` fields.

The handle also accepts the shared `get_address`, `sign_tx`, and `sign_message` request
records for Ethereum, Solana, and Bitcoin, plus `sign_typed_data` for Ethereum EIP-712. The shared `SignTxResult.tx_hash` is the **unsigned signing hash**,
matching Trezor; use `sign_eip1559` for signed transaction bytes and the broadcast transaction
hash. Ethereum message requests accept UTF-8 or hex and return a verified 65-byte signature.
Solana signatures are 64 bytes; off-chain results include the exact signed envelope.

## Sample apps

The macOS, iOS, and Android samples have a **Wallet** selector for Trezor Safe 7, Ledger
Stax, Nano X, and Flex. Select **Ledger Stax**, open the selected chain app, then **Scan**
and **Connect**. The existing **Address**, **Sign**, and **Sign Msg** actions use direct BLE.
Review the configured request before signing; the samples do not broadcast transactions.

Ledger selection offers ETH, BTC, and SOL and disables Trezor pairing, nonce, and
chunkify controls. Switching vendor or device disconnects the previous session and clears
results. **Cancel Request** cancels the host operation; reject any remaining Ledger prompt,
then scan and reconnect. The OS manages Ledger Bluetooth pairing; no THP code is needed.
For EIP-712, select ETH and enable **EIP-712 typed data** in the message inputs (under
**Config** on iOS), edit the JSON, then use **Sign Msg**. The initial JSON is a simple
`Hello from hw-core` message. Ledger clear-signing metadata remains unsupported. BTC disables the multisig and RBF presets.

Apple SDK consumers can use `kit.discover(vendor: .ledgerStax)` and `kit.connect(device:)`,
then the same `WalletSession.getAddress`, `signTx`, `signMessage`, and `signTypedData` methods as Trezor.
Trezor-specific methods throw `Unsupported` for Ledger. Ledger has no THP workflow event
stream, so `events()` completes immediately; the sample shows operation status instead.
Android uses the generated `LedgerSessionHandle` directly.

Operations check the active app before sending chain-specific commands. A wrong app
returns a typed error naming the required chain app. A timed-out, cancelled, or
incomplete exchange retires the session: disconnect and rescan before retrying. FFI rejects
concurrent requests as busy instead of queueing an unexpected signing prompt.

## Verification boundary

Rust workspace tests and formatting/lint pass (the seven Trezor emulator tests remain
ignored). The five Apple SDK tests, two macOS sample UI tests, and four iOS simulator UI
tests pass; the Android APK builds. UI checks cover Ledger selection, BTC availability and unsupported presets, Solana inputs, EIP-712 JSON mode, unsupported controls,
and restoring Trezor controls. macOS UI tests pass when run separately from iOS automation;
an earlier concurrent run failed at initial window discovery. No Android device/emulator was
available for a runtime check. The sample app's latest Stax scan found no device, so sample-app signing remains a physical-device
validation step; the hardware signing results below are from the CLI.

Deterministic tests cover Ed25519 verification of exact transaction/OCMS bytes, official
EIP-712 Mail and independently computed nested-array digest vectors, full structured APDUs, explicit hash
mode, malformed input, and signer mismatch.

Tests cover wire framing, chunking, app selection, response parsing, timeouts, cancellation,
malformed input, signer mismatch, EIP-191 recovery, and EIP-1559 envelope assembly. Direct
connection/reconnection to Stax (BOLOS 1.6.0) and on-device Ethereum address confirmation
were verified on 2026-11-05. With Ethereum app 1.13.0, the following also passed over
BLE at `m/44'/60'/0'/0/0`:

- EIP-191 signing of `hw-core Ledger signing test`, with recovered signer matching the
  previously confirmed device address.
- EIP-1559 signing of a Sepolia (chain ID 11155111) zero-value self-transfer: nonce 0,
  gas limit 21,000, max fee and priority fee both 1 gwei, empty calldata/access list.
  The recovered signer matched the device address and the signed envelope/hash were returned.

Full-JSON EIP-712 signing also passed on the Stax with Ethereum 1.13.0 after enabling
**Raw messages** (blind signing remained disabled). The domain was `hw-core signing test`,
version `1`, Sepolia chain ID `11155111`, with no verifying contract; the message was
`hw-core Ledger EIP-712 test - no authorization`. The SDK and independent ethers verifier
both recovered the previously confirmed Ethereum address. The digest was
`78d33709fe807a06bb56354c947fd985f66da43c0d23180085c011ae69927705`;
changing the message did not recover the expected signer. Hash-only signing has unit-test
coverage but has not been validated on hardware.

With Solana app 1.5.4 on the same Stax, address display at `m/44'/501'/0'/0'` and signing
of a legacy zero-lamport self-transfer passed on 2026-11-05. The test used an all-zero recent
blockhash, and both the SDK and Node's independent Ed25519 verifier checked the exact
118-byte message and returned 64-byte signature. No transaction was broadcast.

OCMS v1 message signing initially failed before review on Solana 1.5.4 with status `0x6a81`.
The [1.5.4 parser](https://github.com/LedgerHQ/app-solana/blob/ca228d73e8c52d0b1214be6c9ac671d47c30faa8/libsol/parser.c)
uses the older version/format/length envelope. After updating the Stax app to **Solana
1.17.1**, the same `hw-core Ledger Solana message test - no authorization` message signed
successfully on 2026-11-05. The SDK and an independent Node Ed25519 verifier checked the
64-byte signature against the exact 103-byte OCMS v1 envelope and the previously confirmed
Solana account; modifying the payload failed verification. The returned `signed_data`
matched the v1 prefix, version, single signer, and UTF-8 message byte for byte.

Solana 1.17.1 is the hardware-validated version for OCMS v1; this does not establish the
minimum compatible version. The SDK reports header rejection with an OCMS compatibility
hint and never retries with different signed bytes.

No test broadcast a transaction. A `btleplug` CoreBluetooth error is still logged during
explicit disconnect, despite successful command completion and subsequent reconnects.
These checks do not establish contract/token clear-signing, other Ledger models, or mobile
runtime coverage. Emulator validation
and platform validation are separate from these deterministic tests.

Protocol references:

- [Ledger device profiles](https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/device-management-kit/src/api/device-model/data/StaticDeviceModelDataSource.ts)
- [Ledger BLE transport](https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/transport/web-ble/src/api/transport/WebBleApduSender.ts)
- [Ethereum APDU specification](https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/apdu.md)
- [Current Ethereum commands](https://github.com/LedgerHQ/device-sdk-ts/tree/develop/packages/signer/signer-eth/src/internal/app-binder/command)

- [Ethereum structured EIP-712 protocol](https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/eip712.md)
- [Solana APDU specification](https://github.com/LedgerHQ/app-solana/blob/develop/doc/api.md)
- [Trezor OCMS envelope](https://github.com/trezor/trezor-firmware/blob/main/core/src/apps/solana/offchain_message.py)
- [Ethereum 1.13.0 raw-review setting](https://github.com/LedgerHQ/app-ethereum/blob/1.13.0/src_nbgl/ui_home.c)
- [Ethereum 1.13.0 unfiltered review gate](https://github.com/LedgerHQ/app-ethereum/blob/1.13.0/src_features/signMessageEIP712/ui_logic.c)

- [Ledger Bitcoin integration and official Rust client](https://github.com/LedgerHQ/app-bitcoin)
