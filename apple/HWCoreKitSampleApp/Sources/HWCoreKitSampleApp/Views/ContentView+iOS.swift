#if os(iOS)
import HWCoreKit
import SwiftUI

struct IOSContentView: View {
    @ObservedObject var viewModel: ContentViewModel
    @State private var showLogSheet = false

    private let actionColumns = [
        GridItem(.flexible(minimum: 120), spacing: 10),
        GridItem(.flexible(minimum: 120), spacing: 10),
    ]

    private let compactInputColumns = [
        GridItem(.flexible(), spacing: 10),
        GridItem(.flexible(), spacing: 10),
    ]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    overviewCard
                    actionCard
                    if !viewModel.devices.isEmpty {
                        deviceCard
                    }
                    addressCard
                    signCard
                    if !viewModel.address.isEmpty || !viewModel.signatureSummary.isEmpty {
                        resultCard
                    }
                    logsCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(
                LinearGradient(
                    colors: [Color(.systemBackground), Color(.secondarySystemBackground)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()
            )
            .navigationBarTitleDisplayMode(.inline)
            .navigationTitle("HWCoreKit")
            .sheet(isPresented: $showLogSheet) {
                NavigationStack {
                    ScrollView {
                        Text(viewModel.logs.joined(separator: "\n"))
                            .font(.system(.footnote, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(16)
                            .textSelection(.enabled)
                            .accessibilityLabel("Logs")
                            .accessibilityIdentifier("logs.text")
                    }
                    .navigationTitle("Logs")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .topBarLeading) {
                            Button("Copy") {
                                viewModel.copyLogsToClipboard()
                            }
                            .accessibilityIdentifier("logs.copy")
                        }
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") {
                                showLogSheet = false
                            }
                        }
                    }
                }
            }
        }
    }

    private var overviewCard: some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                Text("HWCoreKit Sample")
                    .font(.system(.title2, design: .rounded).weight(.bold))
                    .accessibilityIdentifier("title.app")

                Text(viewModel.status)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Status")
                    .accessibilityIdentifier("status.text")

                VStack(alignment: .leading, spacing: 6) {
                    Text("Session Phase")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(viewModel.phaseSummary)
                        .font(.body.weight(.medium))
                }
                .accessibilityLabel("Session phase")
                .accessibilityIdentifier("state.session_phase")

                Picker("Chain", selection: $viewModel.selectedChain) {
                    Text("ETH").tag(Chain.ethereum)
                    Text("BTC").tag(Chain.bitcoin)
                    Text("SOL").tag(Chain.solana)
                }
                .pickerStyle(.segmented)
                .disabled(viewModel.isBusy)
                .accessibilityLabel("Chain")
                .accessibilityIdentifier("picker.chain")
            }
        }
    }

    private var actionCard: some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                Text("Actions")
                    .font(.headline)
                LazyVGrid(columns: actionColumns, spacing: 10) {
                    iosActionButton("Scan", systemImage: "dot.radiowaves.left.and.right", isProminent: true, disabled: viewModel.isBusy, accessibilityID: "action.scan") {
                        Task { await viewModel.scan() }
                    }
                    iosActionButton("Pair Only", systemImage: "link.badge.plus", isProminent: false, disabled: !viewModel.canPairOnly, accessibilityID: "action.pair_only") {
                        Task { await viewModel.pairOnly() }
                    }
                    iosActionButton("Connect", systemImage: "bolt.horizontal.circle", isProminent: true, disabled: !viewModel.canConnect, accessibilityID: "action.connect") {
                        Task { await viewModel.connectReady() }
                    }
                    iosActionButton("Address", systemImage: "location.viewfinder", isProminent: false, disabled: !viewModel.canGetAddress, accessibilityID: "action.address") {
                        Task { await viewModel.fetchAddress() }
                    }
                    iosActionButton("Sign", systemImage: "signature", isProminent: false, disabled: !viewModel.canSign, accessibilityID: "action.sign") {
                        Task { await viewModel.signSampleTransaction() }
                    }
                    iosActionButton("Sign Msg", systemImage: "text.bubble", isProminent: false, disabled: !viewModel.canSignMessage, accessibilityID: "action.sign_message") {
                        Task { await viewModel.signMessage() }
                    }
                    iosActionButton("Disconnect", systemImage: "xmark.circle", isProminent: false, disabled: !viewModel.canDisconnect, accessibilityID: "action.disconnect") {
                        Task { await viewModel.disconnect() }
                    }
                }
            }
        }
    }

    private var deviceCard: some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Device")
                    .font(.headline)

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
    }

    private var addressCard: some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Address Request")
                    .font(.headline)
                textInput("Path (empty uses chain default)", text: $viewModel.addressPathInput)
                    .accessibilityIdentifier("input.address.path")
                Toggle("Show on device", isOn: $viewModel.showAddressOnDevice)
                    .accessibilityIdentifier("toggle.address.show_on_device")
                Toggle("Include public key", isOn: $viewModel.includeAddressPublicKey)
                    .accessibilityIdentifier("toggle.address.include_public_key")
                Toggle("Chunkify", isOn: $viewModel.addressChunkify)
                    .accessibilityIdentifier("toggle.address.chunkify")
            }
        }
    }

    private var signCard: some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Sign Request")
                    .font(.headline)

                signInputs

                Divider()

                messageSignInputs

                Divider()

                Text("Preview")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                ScrollView(.horizontal) {
                    Text(viewModel.signPreview)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("sign.preview")
                }
            }
        }
    }

    private var resultCard: some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                if !viewModel.address.isEmpty {
                    Text("Address")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(viewModel.address)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .accessibilityLabel("Address")
                        .accessibilityIdentifier("result.address")
                    Button("Copy Address") {
                        viewModel.copyAddressToClipboard()
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("result.address.copy")
                }

                if !viewModel.signatureSummary.isEmpty {
                    if !viewModel.address.isEmpty {
                        Divider()
                    }
                    Text("Signature")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
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
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("result.signature.copy")
                        Button("Export Signature") {
                            viewModel.exportSignatureToFile()
                        }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("result.signature.export")
                    }
                }
            }
        }
    }

    private var logsCard: some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Logs")
                        .font(.headline)
                    Spacer()
                    Button("Open") {
                        showLogSheet = true
                    }
                    .buttonStyle(.bordered)
                }
                HStack(spacing: 8) {
                    Button("Copy Logs") {
                        viewModel.copyLogsToClipboard()
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("logs.copy")
                }
                Text(logPreview)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel("Logs")
                    .accessibilityIdentifier("logs.text")
            }
        }
    }

    private var logPreview: String {
        let lines = viewModel.logs.suffix(6)
        if lines.isEmpty {
            return "No logs yet."
        }
        return lines.joined(separator: "\n")
    }

    @ViewBuilder
    private var signInputs: some View {
        switch viewModel.selectedChain {
        case .ethereum:
            textInput("Path (ETH)", text: $viewModel.ethSignPathInput)
                .accessibilityIdentifier("input.sign.eth.path")
            textInput("To", text: $viewModel.ethTo)
                .accessibilityIdentifier("input.sign.eth.to")
            LazyVGrid(columns: compactInputColumns, spacing: 10) {
                textInput("Value", text: $viewModel.ethValue)
                    .accessibilityIdentifier("input.sign.eth.value")
                textInput("Nonce", text: $viewModel.ethNonce)
                    .accessibilityIdentifier("input.sign.eth.nonce")
                textInput("Chain ID", text: $viewModel.ethChainId)
                    .accessibilityIdentifier("input.sign.eth.chain_id")
                textInput("Gas Limit", text: $viewModel.ethGasLimit)
                    .accessibilityIdentifier("input.sign.eth.gas_limit")
                textInput("Max Fee", text: $viewModel.ethMaxFeePerGas)
                    .accessibilityIdentifier("input.sign.eth.max_fee")
                textInput("Priority Fee", text: $viewModel.ethMaxPriorityFee)
                    .accessibilityIdentifier("input.sign.eth.priority_fee")
            }
            textInput("Data", text: $viewModel.ethData)
                .accessibilityIdentifier("input.sign.eth.data")
            Toggle("Chunkify", isOn: $viewModel.ethChunkify)
                .accessibilityIdentifier("toggle.sign.eth.chunkify")
        case .solana:
            textInput("Path (SOL)", text: $viewModel.solSignPathInput)
                .accessibilityIdentifier("input.sign.sol.path")
            textInput("Serialized Tx Hex", text: $viewModel.solSerializedTxHex)
                .accessibilityIdentifier("input.sign.sol.tx_hex")
            Toggle("Chunkify", isOn: $viewModel.solChunkify)
                .accessibilityIdentifier("toggle.sign.sol.chunkify")
        case .bitcoin:
            Text("Transaction JSON")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            TextEditor(text: $viewModel.btcTxJsonInput)
                .font(.system(.footnote, design: .monospaced))
                .frame(minHeight: 180)
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Color(.secondarySystemBackground))
                )
                .accessibilityIdentifier("input.sign.btc.tx_json")
            Text("BTC signing requires ref_txs that match each input prev_hash/prev_index.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var messageSignInputs: some View {
        if viewModel.selectedChain == .ethereum || viewModel.selectedChain == .bitcoin {
            Text("Message Sign")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            textInput("Path (\(viewModel.chainLabel(viewModel.selectedChain)))", text: $viewModel.messageSignPathInput)
                .accessibilityIdentifier("input.message.path")
            textInput("Message", text: $viewModel.messageSignPayload)
                .accessibilityIdentifier("input.message.payload")
            Toggle("Message is hex", isOn: $viewModel.messageSignIsHex)
                .accessibilityIdentifier("toggle.message.hex")
            Toggle("Chunkify", isOn: $viewModel.messageSignChunkify)
                .accessibilityIdentifier("toggle.message.chunkify")
        } else {
            Text("Message signing is available for ETH/BTC only.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            content()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color(.systemBackground).opacity(0.95))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color(.separator).opacity(0.25), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 6)
    }

    @ViewBuilder
    private func iosActionButton(
        _ title: String,
        systemImage: String,
        isProminent: Bool,
        disabled: Bool,
        accessibilityID: String,
        action: @escaping () -> Void
    ) -> some View {
        if isProminent {
            Button(action: action) {
                Label(title, systemImage: systemImage)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(disabled)
            .accessibilityIdentifier(accessibilityID)
        } else {
            Button(action: action) {
                Label(title, systemImage: systemImage)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .disabled(disabled)
            .accessibilityIdentifier(accessibilityID)
        }
    }

    private func textInput(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled(true)
            .font(.system(.body, design: .rounded))
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color(.secondarySystemBackground))
            )
    }
}
#endif
