import SwiftUI
import HWCoreKit

struct ContentView: View {
    @StateObject var viewModel = ContentViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("HWCoreKit Sample")
                .font(.title2)
                .bold()
                .accessibilityIdentifier("title.app")

            Text(viewModel.status)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .accessibilityLabel("Status")
                .accessibilityIdentifier("status.text")

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

                Button("Disconnect") {
                    Task { await viewModel.disconnect() }
                }
                .disabled(!viewModel.canDisconnect)
                .accessibilityLabel("Disconnect")
                .accessibilityIdentifier("action.disconnect")
            }

            Picker("Chain", selection: $viewModel.selectedChain) {
                Text("ETH").tag(Chain.ethereum)
                Text("BTC").tag(Chain.bitcoin)
                Text("SOL").tag(Chain.solana)
            }
            .pickerStyle(.segmented)
            .disabled(viewModel.isBusy)
            .accessibilityLabel("Chain")
            .accessibilityIdentifier("picker.chain")

            if !viewModel.devices.isEmpty {
                Picker("Device", selection: $viewModel.selectedDeviceIndex) {
                    ForEach(Array(viewModel.devices.enumerated()), id: \.offset) { index, device in
                        Text("\(device.name ?? "Unknown") (\(device.id))").tag(index)
                    }
                }
                .pickerStyle(.menu)
                .accessibilityLabel("Device")
                .accessibilityIdentifier("picker.device")
            }

            Text("Session Phase: \(viewModel.phaseSummary)")
                .font(.footnote)
                .foregroundColor(.secondary)
                .accessibilityLabel("Session phase")
                .accessibilityIdentifier("state.session_phase")

            if !viewModel.address.isEmpty {
                Text("Address: \(viewModel.address)")
                    .font(.system(.body, design: .monospaced))
                    .accessibilityLabel("Address")
                    .accessibilityIdentifier("result.address")
            }

            if !viewModel.signatureSummary.isEmpty {
                ScrollView(.horizontal) {
                    Text(viewModel.signatureSummary)
                        .font(.system(.footnote, design: .monospaced))
                        .accessibilityLabel("Signature")
                        .accessibilityIdentifier("result.signature")
                }
            }

            Divider()

            ScrollView([.horizontal, .vertical]) {
                Text(viewModel.logs.joined(separator: "\n"))
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .accessibilityLabel("Logs")
                    .accessibilityIdentifier("logs.text")
            }
        }
        .padding(16)
        .frame(minWidth: 980, minHeight: 700)
        .task {
            await viewModel.bootstrap()
        }
        .alert("Pairing Code", isPresented: $viewModel.showPairingAlert) {
            TextField("123456", text: $viewModel.pairingCodeInput)
                .accessibilityLabel("Pairing code")
                .accessibilityIdentifier("pairing.code_input")
            Button("Submit") {
                Task { await viewModel.submitPairingCodeFromAlert() }
            }
            .accessibilityIdentifier("pairing.submit")
            Button("Cancel", role: .cancel) {
                viewModel.cancelPairingCodePrompt()
            }
            .accessibilityIdentifier("pairing.cancel")
        } message: {
            Text(
                viewModel.pairingPromptMessage.isEmpty
                    ? "Enter the 6-digit code shown on the device."
                    : viewModel.pairingPromptMessage
            )
            .accessibilityIdentifier("pairing.prompt")
        }
    }
}
