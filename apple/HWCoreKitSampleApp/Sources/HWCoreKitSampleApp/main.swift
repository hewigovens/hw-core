import HWCoreKit
import SwiftUI

@MainActor
final class SampleViewModel: ObservableObject {
    @Published var status = "Idle"
    @Published var devices: [WalletDevice] = []
    @Published var selectedDeviceIndex = 0
    @Published var pairingCode = ""
    @Published var pairingPrompt = ""
    @Published var address = ""
    @Published var signatureSummary = ""
    @Published var logs: [String] = []

    private var coreKit: HWCoreKit?
    private var session: WalletSession?
    private var eventTask: Task<Void, Never>?

    deinit {
        eventTask?.cancel()
    }

    func bootstrap() async {
        if coreKit != nil {
            return
        }

        do {
            coreKit = try await HWCoreKit.create(
                config: HWCoreConfig(
                    hostName: Host.current().localizedName ?? "macOS",
                    appName: "hw-core/sample"
                )
            )
            status = "HWCoreKit initialized"
            appendLog("initialized kit")
        } catch {
            handleError(error, prefix: "bootstrap")
        }
    }

    func scan() async {
        await bootstrap()
        guard let coreKit else { return }

        do {
            status = "Scanning for devices..."
            devices = try await coreKit.discoverTrezor(timeoutMs: 8_000)
            selectedDeviceIndex = 0
            status = "Found \(devices.count) device(s)"
            appendLog("scan complete: \(devices.count) device(s)")
        } catch {
            handleError(error, prefix: "scan")
        }
    }

    func connectSelected() async {
        guard let coreKit else {
            await bootstrap()
            return
        }
        guard devices.indices.contains(selectedDeviceIndex) else {
            status = "No device selected"
            return
        }

        do {
            let selected = devices[selectedDeviceIndex]
            session = try await coreKit.connect(device: selected)
            status = "Connected: \(selected.id)"
            appendLog("connected: \(selected.id)")
            startEventStream()
        } catch {
            handleError(error, prefix: "connect")
        }
    }

    func prepareHandshake() async {
        guard let session else {
            status = "Connect first"
            return
        }

        do {
            status = "Preparing channel + handshake..."
            let handshakeState = try await session.prepareChannelAndHandshake()
            switch handshakeState {
            case .ready:
                status = "Session already paired and ready"
                pairingPrompt = ""
            case let .pairingRequired(prompt):
                status = "Pairing code required"
                pairingPrompt = prompt.message
            case let .connectionConfirmationRequired(prompt):
                status = "Connection confirmation required"
                pairingPrompt = prompt.message
            }
            appendLog("handshake state: \(status)")
        } catch {
            handleError(error, prefix: "prepareHandshake")
        }
    }

    func submitPairingCode() async {
        guard let session else {
            status = "Connect first"
            return
        }

        do {
            let progress = try await session.submitPairingCode(pairingCode)
            status = "Pairing progress: \(progress.kind)"
            appendLog(progress.message)
            pairingPrompt = ""
        } catch {
            handleError(error, prefix: "submitPairingCode")
        }
    }

    func confirmConnection() async {
        guard let session else {
            status = "Connect first"
            return
        }

        do {
            let progress = try await session.confirmPairedConnection()
            status = "Connection confirmed"
            appendLog(progress.message)
            pairingPrompt = ""
        } catch {
            handleError(error, prefix: "confirmPairedConnection")
        }
    }

    func createWalletSession() async {
        guard let session else {
            status = "Connect first"
            return
        }

        do {
            try await session.createWalletSession()
            status = "Wallet session created"
            appendLog("wallet session ready")
        } catch {
            handleError(error, prefix: "createWalletSession")
        }
    }

    func fetchAddress() async {
        guard let session else {
            status = "Connect first"
            return
        }

        do {
            let result = try await session.getEthereumAddress(includePublicKey: true)
            address = result.address
            status = "ETH address received"
            appendLog("address: \(result.address)")
        } catch {
            handleError(error, prefix: "getEthereumAddress")
        }
    }

    func signSampleTransaction() async {
        guard let session else {
            status = "Connect first"
            return
        }

        let request = EthereumSignRequest(
            to: "0x000000000000000000000000000000000000dead",
            gasLimit: "0x5208",
            chainId: 1,
            maxFeePerGas: "0x3b9aca00",
            maxPriorityFee: "0x59682f00"
        )

        do {
            let result = try await session.signEthereumTx(request)
            signatureSummary = "v=\(result.v) r=0x\(result.r.map { String(format: "%02x", $0) }.joined()) s=0x\(result.s.map { String(format: "%02x", $0) }.joined())"
            status = "Transaction signed"
            appendLog("sign result: \(signatureSummary)")
            if let recovered = result.recoveredAddress {
                appendLog("recovered: \(recovered)")
            }
        } catch {
            handleError(error, prefix: "signEthereumTx")
        }
    }

    func disconnect() async {
        guard let session else {
            return
        }
        await session.disconnect()
        self.session = nil
        eventTask?.cancel()
        eventTask = nil
        status = "Disconnected"
        appendLog("disconnected")
    }

    private func startEventStream() {
        eventTask?.cancel()
        guard let session else { return }

        eventTask = Task {
            for await event in session.events(timeoutMs: 500) {
                appendLog("event [\(event.code)] \(event.message)")
            }
        }
    }

    private func appendLog(_ line: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        logs.append("[\(timestamp)] \(line)")
    }

    private func handleError(_ error: Error, prefix: String) {
        status = "Error: \(prefix)"
        appendLog("\(prefix) failed: \(error.localizedDescription)")
    }
}

struct ContentView: View {
    @StateObject var viewModel = SampleViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("HWCoreKit Sample")
                .font(.title2)
                .bold()

            Text(viewModel.status)
                .font(.subheadline)
                .foregroundColor(.secondary)

            HStack(spacing: 8) {
                Button("Scan") {
                    Task { await viewModel.scan() }
                }
                .keyboardShortcut("s", modifiers: [.command])

                Button("Connect") {
                    Task { await viewModel.connectSelected() }
                }

                Button("Prepare") {
                    Task { await viewModel.prepareHandshake() }
                }

                Button("Confirm") {
                    Task { await viewModel.confirmConnection() }
                }

                Button("Create Session") {
                    Task { await viewModel.createWalletSession() }
                }

                Button("Address") {
                    Task { await viewModel.fetchAddress() }
                }

                Button("Sign") {
                    Task { await viewModel.signSampleTransaction() }
                }

                Button("Disconnect") {
                    Task { await viewModel.disconnect() }
                }
            }

            if !viewModel.devices.isEmpty {
                Picker("Device", selection: $viewModel.selectedDeviceIndex) {
                    ForEach(Array(viewModel.devices.enumerated()), id: \.offset) { index, device in
                        Text("\(device.name ?? "Unknown") (\(device.id))").tag(index)
                    }
                }
                .pickerStyle(.menu)
            }

            HStack {
                Text("Pairing code:")
                TextField("123456", text: $viewModel.pairingCode)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                Button("Submit Code") {
                    Task { await viewModel.submitPairingCode() }
                }
            }

            if !viewModel.pairingPrompt.isEmpty {
                Text("Prompt: \(viewModel.pairingPrompt)")
                    .font(.footnote)
            }

            if !viewModel.address.isEmpty {
                Text("Address: \(viewModel.address)")
                    .font(.system(.body, design: .monospaced))
            }

            if !viewModel.signatureSummary.isEmpty {
                ScrollView(.horizontal) {
                    Text(viewModel.signatureSummary)
                        .font(.system(.footnote, design: .monospaced))
                }
            }

            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(viewModel.logs.indices, id: \.self) { idx in
                        Text(viewModel.logs[idx])
                            .font(.system(.footnote, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(16)
        .frame(minWidth: 980, minHeight: 700)
        .task {
            await viewModel.bootstrap()
        }
    }
}

@main
struct HWCoreKitSampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
