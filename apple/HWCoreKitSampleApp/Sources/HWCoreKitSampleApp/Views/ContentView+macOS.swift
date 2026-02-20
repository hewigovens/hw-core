#if os(macOS)
import HWCoreKit
import SwiftUI

struct MacContentView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                headerCard
                actionCard
                if !viewModel.devices.isEmpty {
                    deviceCard
                }
                detailCards
                logsCard
            }
            .padding(18)
        }
        .background(
            LinearGradient(
                colors: [Color(nsColor: .windowBackgroundColor), Color(nsColor: .controlBackgroundColor)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .frame(minWidth: 980, minHeight: 700)
    }

    private var headerCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text("HWCoreKit Sample")
                    .font(.system(.title2, design: .rounded).weight(.bold))
                    .accessibilityIdentifier("title.app")

                Text(viewModel.status)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Status")
                    .accessibilityIdentifier("status.text")

                Picker("Chain", selection: $viewModel.selectedChain) {
                    Text("ETH").tag(Chain.ethereum)
                    Text("BTC").tag(Chain.bitcoin)
                    Text("SOL").tag(Chain.solana)
                }
                .pickerStyle(.segmented)
                .disabled(viewModel.isBusy)
                .accessibilityLabel("Chain")
                .accessibilityIdentifier("picker.chain")

                Text("Session Phase: \(viewModel.phaseSummary)")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Session phase")
                    .accessibilityIdentifier("state.session_phase")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var actionCard: some View {
        GroupBox("Actions") {
            HStack(spacing: 8) {
                Button("Scan") {
                    Task { await viewModel.scan() }
                }
                .keyboardShortcut("s", modifiers: [.command])
                .disabled(viewModel.isBusy)
                .accessibilityLabel("Scan")
                .accessibilityIdentifier("action.scan")

                Button("Pair Only") {
                    Task { await viewModel.pairOnly() }
                }
                .disabled(!viewModel.canPairOnly)
                .accessibilityLabel("Pair only")
                .accessibilityIdentifier("action.pair_only")

                Button("Connect") {
                    Task { await viewModel.connectReady() }
                }
                .disabled(!viewModel.canConnect)
                .accessibilityLabel("Connect")
                .accessibilityIdentifier("action.connect")

                Button("Address") {
                    Task { await viewModel.fetchAddress() }
                }
                .disabled(!viewModel.canGetAddress)
                .accessibilityLabel("Get address")
                .accessibilityIdentifier("action.address")

                Button("Sign") {
                    Task { await viewModel.signSampleTransaction() }
                }
                .disabled(!viewModel.canSign)
                .accessibilityLabel("Sign transaction")
                .accessibilityIdentifier("action.sign")

                Button("Sign Msg") {
                    Task { await viewModel.signMessage() }
                }
                .disabled(!viewModel.canSignMessage)
                .accessibilityLabel("Sign message")
                .accessibilityIdentifier("action.sign_message")

                Button("Disconnect") {
                    Task { await viewModel.disconnect() }
                }
                .disabled(!viewModel.canDisconnect)
                .accessibilityLabel("Disconnect")
                .accessibilityIdentifier("action.disconnect")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var deviceCard: some View {
        GroupBox("Device") {
            Picker("Device", selection: $viewModel.selectedDeviceIndex) {
                ForEach(Array(viewModel.devices.enumerated()), id: \.offset) { index, device in
                    Text("\(device.name ?? "Unknown") (\(device.id))").tag(index)
                }
            }
            .pickerStyle(.menu)
            .accessibilityLabel("Device")
            .accessibilityIdentifier("picker.device")
        }
    }

    private var detailCards: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                GroupBox("Address Request") {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Path (empty uses chain default)", text: $viewModel.addressPathInput)
                            .textFieldStyle(.roundedBorder)
                            .accessibilityIdentifier("input.address.path")
                        HStack(spacing: 16) {
                            Toggle("Show on device", isOn: $viewModel.showAddressOnDevice)
                                .accessibilityIdentifier("toggle.address.show_on_device")
                            Toggle("Include public key", isOn: $viewModel.includeAddressPublicKey)
                                .accessibilityIdentifier("toggle.address.include_public_key")
                            Toggle("Chunkify", isOn: $viewModel.addressChunkify)
                                .accessibilityIdentifier("toggle.address.chunkify")
                        }
                    }
                }

                GroupBox("Sign Request") {
                    VStack(alignment: .leading, spacing: 8) {
                        signInputs
                        Divider()
                        messageSignInputs
                        Divider()
                        Text("Preview")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        ScrollView(.horizontal) {
                            Text(viewModel.signPreview)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                                .accessibilityIdentifier("sign.preview")
                        }
                    }
                }

                if !viewModel.address.isEmpty {
                    HStack(spacing: 8) {
                        Text("Address: \(viewModel.address)")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .accessibilityLabel("Address")
                            .accessibilityIdentifier("result.address")
                        Button("Copy") {
                            viewModel.copyAddressToClipboard()
                        }
                        .accessibilityIdentifier("result.address.copy")
                    }
                }

                if !viewModel.signatureSummary.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ScrollView(.horizontal) {
                            Text(viewModel.signatureSummary)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                                .accessibilityLabel("Signature")
                                .accessibilityIdentifier("result.signature")
                        }
                        HStack(spacing: 8) {
                            Button("Copy Signature") {
                                viewModel.copySignatureToClipboard()
                            }
                            .accessibilityIdentifier("result.signature.copy")
                            Button("Export Signature") {
                                viewModel.exportSignatureToFile()
                            }
                            .accessibilityIdentifier("result.signature.export")
                        }
                    }
                }
            }
        }
    }

    private var logsCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Logs")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Copy Logs") {
                        viewModel.copyLogsToClipboard()
                    }
                    .accessibilityIdentifier("logs.copy")
                }

                ScrollView([.horizontal, .vertical]) {
                    Text(viewModel.logs.joined(separator: "\n"))
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .accessibilityLabel("Logs")
                        .accessibilityIdentifier("logs.text")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private var signInputs: some View {
        switch viewModel.selectedChain {
        case .ethereum:
            TextField("Path (ETH)", text: $viewModel.ethSignPathInput)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.sign.eth.path")
            TextField("To", text: $viewModel.ethTo)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.sign.eth.to")
            HStack(spacing: 8) {
                TextField("Value", text: $viewModel.ethValue)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.value")
                TextField("Nonce", text: $viewModel.ethNonce)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.nonce")
                TextField("Chain ID", text: $viewModel.ethChainId)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.chain_id")
            }
            HStack(spacing: 8) {
                TextField("Gas Limit", text: $viewModel.ethGasLimit)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.gas_limit")
                TextField("Max Fee", text: $viewModel.ethMaxFeePerGas)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.max_fee")
                TextField("Priority Fee", text: $viewModel.ethMaxPriorityFee)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("input.sign.eth.priority_fee")
            }
            TextField("Data", text: $viewModel.ethData)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.sign.eth.data")
            Toggle("Chunkify", isOn: $viewModel.ethChunkify)
                .accessibilityIdentifier("toggle.sign.eth.chunkify")
        case .solana:
            TextField("Path (SOL)", text: $viewModel.solSignPathInput)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.sign.sol.path")
            TextField("Serialized Tx Hex", text: $viewModel.solSerializedTxHex)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.sign.sol.tx_hex")
            Toggle("Chunkify", isOn: $viewModel.solChunkify)
                .accessibilityIdentifier("toggle.sign.sol.chunkify")
        case .bitcoin:
            Text("Transaction JSON")
                .font(.footnote)
                .foregroundStyle(.secondary)
            TextEditor(text: $viewModel.btcTxJsonInput)
                .font(.system(.footnote, design: .monospaced))
                .frame(minHeight: 140)
                .accessibilityIdentifier("input.sign.btc.tx_json")
            Text("Advanced BTC flows should preload all required input/output context in wallet code.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var messageSignInputs: some View {
        if viewModel.selectedChain == .ethereum || viewModel.selectedChain == .bitcoin {
            Text("Message Sign")
                .font(.footnote)
                .foregroundStyle(.secondary)
            TextField("Path (\(viewModel.chainLabel(viewModel.selectedChain)))", text: $viewModel.messageSignPathInput)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.message.path")
            TextField("Message", text: $viewModel.messageSignPayload)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("input.message.payload")
            HStack(spacing: 8) {
                Toggle("Message is hex", isOn: $viewModel.messageSignIsHex)
                    .accessibilityIdentifier("toggle.message.hex")
                Toggle("Chunkify", isOn: $viewModel.messageSignChunkify)
                    .accessibilityIdentifier("toggle.message.chunkify")
            }
        } else {
            Text("Message signing is available for ETH/BTC only.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}
#endif
