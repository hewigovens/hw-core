import Foundation
import HWCoreKit
import SwiftUI
import struct HWCoreFFI.SessionState
import enum HWCoreFFI.SessionPhase
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

@MainActor
final class ContentViewModel: ObservableObject {
    @Published var status = "Idle"
    @Published var devices: [WalletDevice] = []
    @Published var selectedDeviceIndex = 0
    @Published var selectedChain: Chain = .ethereum
    @Published var phaseSummary = "No session"
    @Published var pairingPromptMessage = ""
    @Published var pairingCodeInput = ""
    @Published var showPairingAlert = false
    @Published var isBusy = false
    @Published var address = ""
    @Published var signatureSummary = ""
    @Published var logs: [String] = []
    @Published var addressPathInput: String
    @Published var showAddressOnDevice = true
    @Published var includeAddressPublicKey = false
    @Published var addressChunkify = false
    @Published var ethSignPathInput: String
    @Published var ethTo = "0x000000000000000000000000000000000000dead"
    @Published var ethValue = "0x0"
    @Published var ethNonce = "0x0"
    @Published var ethGasLimit = "0x5208"
    @Published var ethChainId = "1"
    @Published var ethData = "0x"
    @Published var ethMaxFeePerGas = "0x3b9aca00"
    @Published var ethMaxPriorityFee = "0x59682f00"
    @Published var ethChunkify = false
    @Published var messageSignPathInput: String
    @Published var messageSignPayload = "hello from hw-core"
    @Published var messageSignIsHex = false
    @Published var messageSignChunkify = false
    @Published var solSignPathInput: String
    @Published var solSerializedTxHex: String
    @Published var solChunkify = false
    @Published var btcTxJsonInput: String

    private var coreKit: HWCoreKit?
    private var session: WalletSession?
    private var sessionState: SessionState?
    private var eventTask: Task<Void, Never>?
    private var pendingPairingFlow: PendingPairingFlow?
    private var storagePath: String?
    private var pendingRecoveryDeviceID: String?
    private var shouldRecoverOnActive = false

    private enum PendingPairingFlow {
        case pairOnly
        case connectReady
    }

    private struct StorageSnapshotSummary {
        let schemaVersion: Int
        let hasStaticKey: Bool
        let knownCredentialCount: Int
    }

    private struct InputValidationError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    // Deterministic SOL legacy-message fixture signed by address:
    // FsTN1tNGk2HAYFggctuT5ZtbdKxmVg9WjEDH9DQAyGFb (m/44'/501'/0'/0')
    private static let defaultSolanaTxHex = "01000103dcf07724e5ed851704cc5e8528f4b08d3ebb6184d327c0ea17b88bb3aaa7c31a11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000222222222222222222222222222222222222222222222222222222222222222201020200010c020000000100000000000000"
    private static let defaultBitcoinTxJson = """
    {
      "version": 2,
      "lock_time": 0,
      "inputs": [
        {
          "path": "m/84'/0'/0'/0/0",
          "prev_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
          "prev_index": 0,
          "amount": "1000",
          "sequence": 4294967295,
          "script_type": "spendwitness"
        }
      ],
      "outputs": [
        {
          "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
          "amount": "900",
          "script_type": "paytoaddress"
        }
      ],
      "ref_txs": [
        {
          "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
          "version": 2,
          "lock_time": 0,
          "inputs": [
            {
              "prev_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "prev_index": 0,
              "script_sig": "",
              "sequence": 4294967295
            }
          ],
          "bin_outputs": [
            {
              "amount": "1000",
              "script_pubkey": "001400112233445566778899aabbccddeeff00112233"
            }
          ]
        }
      ]
    }
    """

    init() {
        let ethPath = Chain.ethereum.defaultPath
        let solPath = Chain.solana.defaultPath
        let btcPath = Chain.bitcoin.defaultPath
        addressPathInput = ethPath
        ethSignPathInput = ethPath
        messageSignPathInput = ethPath
        solSignPathInput = solPath
        solSerializedTxHex = Self.defaultSolanaTxHex
        btcTxJsonInput = Self.defaultBitcoinTxJson
        if selectedChain == .bitcoin {
            messageSignPathInput = btcPath
        }
    }

    deinit {
        eventTask?.cancel()
    }

    var hasSelectedDevice: Bool {
        devices.indices.contains(selectedDeviceIndex)
    }

    var canPairOnly: Bool {
        guard !isBusy, hasSelectedDevice else { return false }
        guard session != nil else { return true }
        return sessionState?.canPairOnly ?? true
    }

    var canConnect: Bool {
        guard !isBusy, hasSelectedDevice else { return false }
        guard session != nil else { return true }
        return sessionState?.canConnect ?? true
    }

    var canGetAddress: Bool {
        !isBusy && session != nil && (sessionState?.canGetAddress ?? false)
    }

    var canSign: Bool {
        !isBusy && session != nil && (sessionState?.canSignTx ?? false)
    }

    var canSignMessage: Bool {
        canSign && selectedChain != .solana
    }

    var canDisconnect: Bool {
        !isBusy && session != nil
    }

    func bootstrap() async {
        if coreKit != nil {
            return
        }

        do {
            let path = defaultStoragePath()
            storagePath = path
            appendLog("storage path: \(path)")
            if let snapshot = loadStorageSnapshotSummary(path: path) {
                appendLog(
                    "storage snapshot: schema=\(snapshot.schemaVersion) static_key=\(snapshot.hasStaticKey) known_credentials=\(snapshot.knownCredentialCount)"
                )
            } else {
                appendLog("storage snapshot: unavailable or unreadable")
            }
            coreKit = try await HWCoreKit.create(
                config: HWCoreConfig(
                    hostName: defaultHostName(),
                    appName: "hw-core/cli",
                    storagePath: path
                )
            )
            status = "HWCoreKit initialized"
            appendLog("initialized kit")
        } catch {
            handleError(error, prefix: "bootstrap")
        }
    }

    func scan() async {
        await runAction(prefix: "scan") { [self] in
            await self.bootstrap()
            guard let coreKit else { return }

            status = "Scanning for devices..."
            devices = try await coreKit.discoverTrezor(timeoutMs: 8_000)
            selectedDeviceIndex = 0
            status = "Found \(devices.count) device(s)"
            appendLog("scan complete: \(devices.count) device(s)")

            if session != nil {
                await disconnectSession()
            }
        }
    }

    func pairOnly() async {
        await runAction(prefix: "pairOnly") { [self] in
            try clearPairingStorage()
            await disconnectSession()
            try await ensureConnectedSession()
            guard let session else { return }
            let state = try await session.pairOnly()
            applySessionState(state, trigger: .pairOnly)
            if state.requiresPairingCode {
                try await startPairingPrompt(trigger: .pairOnly)
            }
        }
    }

    func connectReady() async {
        await runAction(prefix: "connectReady") { [self] in
            try await ensureConnectedSession()
            guard let session else { return }
            let state = try await session.connectReady(tryToUnlock: true)
            applySessionState(state, trigger: .connectReady)
            if state.requiresPairingCode {
                try await startPairingPrompt(trigger: .connectReady)
            }
        }
    }

    func submitPairingCodeFromAlert() async {
        await runAction(prefix: "submitPairingCode") { [self] in
            guard let session else {
                status = "Connect first"
                return
            }

            let code = pairingCodeInput.trimmingCharacters(in: .whitespacesAndNewlines)
            let progress = try await session.submitPairingCode(code)
            appendLog(progress.message)
            showPairingAlert = false
            pairingCodeInput = ""
            pairingPromptMessage = ""

            guard let flow = pendingPairingFlow else {
                try await refreshSessionState()
                return
            }
            pendingPairingFlow = nil

            switch flow {
            case .pairOnly:
                let state = try await session.pairOnly()
                applySessionState(state, trigger: .pairOnly)
            case .connectReady:
                let state = try await session.connectReady(tryToUnlock: true)
                applySessionState(state, trigger: .connectReady)
            }
        }
    }

    func cancelPairingCodePrompt() {
        showPairingAlert = false
        pairingCodeInput = ""
        pendingPairingFlow = nil
        status = "Pairing prompt dismissed"
        appendLog("pairing prompt dismissed")
    }

    func fetchAddress() async {
        await runAction(prefix: "getAddress") { [self] in
            guard let session else {
                status = "Connect first"
                return
            }
            guard sessionState?.canGetAddress == true else {
                status = "Connect first"
                return
            }

            let result = try await session.getAddress(
                chain: selectedChain,
                path: resolvedPath(addressPathInput, chain: selectedChain),
                showOnDevice: showAddressOnDevice,
                includePublicKey: includeAddressPublicKey,
                chunkify: addressChunkify
            )
            address = result.address
            status = "Address received"
            appendLog("address (\(chainLabel(selectedChain))): \(result.address)")
        }
    }

    func signSampleTransaction() async {
        await runAction(prefix: "signTx") { [self] in
            guard let session else {
                status = "Connect first"
                return
            }
            guard sessionState?.canSignTx == true else {
                status = "Connect first"
                return
            }
            let request = try await buildSignRequest(chain: selectedChain, session: session)
            appendLog("sign preview: \(signPreview)")
            let result = try await session.signTx(request)
            signatureSummary = describeSignResult(result, chain: selectedChain)
            status = "Transaction signed"
            appendLog("sign (\(chainLabel(selectedChain))) result: \(signatureSummary)")
            if let recovered = result.recoveredAddress {
                appendLog("recovered: \(recovered)")
            }
        }
    }

    func signMessage() async {
        await runAction(prefix: "signMessage") { [self] in
            guard let session else {
                status = "Connect first"
                return
            }
            guard sessionState?.canSignTx == true else {
                status = "Connect first"
                return
            }
            guard selectedChain != .solana else {
                status = "Message signing is available for ETH/BTC only"
                return
            }

            let request = try buildMessageSignRequest(chain: selectedChain)
            appendLog("message sign preview: \(messageSignPreview)")
            let result = try await session.signMessage(request)
            signatureSummary = describeMessageSignResult(result)
            status = "Message signed"
            appendLog("message sign (\(chainLabel(selectedChain))) result: \(signatureSummary)")
        }
    }

    func selectedChainDidChange() {
        addressPathInput = defaultPath(for: selectedChain)
        messageSignPathInput = defaultPath(for: selectedChain)
        status = "Selected chain: \(chainLabel(selectedChain))"
    }

    var signPreview: String {
        switch selectedChain {
        case .ethereum:
            return "ETH path=\(resolvedPath(ethSignPathInput, chain: .ethereum)) to=\(ethTo) value=\(ethValue) nonce=\(ethNonce) gas_limit=\(ethGasLimit) chain_id=\(ethChainId)"
        case .solana:
            return "SOL path=\(resolvedPath(solSignPathInput, chain: .solana)) tx_hex_bytes=\(sanitizedHex(solSerializedTxHex).count / 2)"
        case .bitcoin:
            if let summary = summarizeBitcoinTxJson(btcTxJsonInput) {
                return "BTC \(summary)"
            }
            return "BTC invalid tx JSON"
        }
    }

    var messageSignPreview: String {
        switch selectedChain {
        case .ethereum:
            return "ETH path=\(resolvedPath(messageSignPathInput, chain: .ethereum)) hex=\(messageSignIsHex) bytes=\(messageSignPayload.utf8.count)"
        case .bitcoin:
            return "BTC path=\(resolvedPath(messageSignPathInput, chain: .bitcoin)) hex=\(messageSignIsHex) bytes=\(messageSignPayload.utf8.count)"
        case .solana:
            return "SOL message signing not supported"
        }
    }

    func copyAddressToClipboard() {
        copyToClipboard(address, emptyMessage: "No address to copy", successLabel: "address")
    }

    func copySignatureToClipboard() {
        copyToClipboard(signatureSummary, emptyMessage: "No signature to copy", successLabel: "signature")
    }

    func copyLogsToClipboard() {
        copyToClipboard(logs.joined(separator: "\n"), emptyMessage: "No logs to copy", successLabel: "logs")
    }

    func exportSignatureToFile() {
        guard !signatureSummary.isEmpty else {
            status = "No signature to export"
            return
        }
        #if canImport(AppKit)
        let panel = NSSavePanel()
        panel.title = "Export Signature"
        panel.nameFieldStringValue = "signature-\(chainLabel(selectedChain).lowercased()).txt"
        panel.allowedContentTypes = [.plainText]
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try signatureSummary.write(to: url, atomically: true, encoding: .utf8)
                status = "Signature exported"
                appendLog("signature exported: \(url.path)")
            } catch {
                status = "Export failed"
                appendLog("export failed: \(error.localizedDescription)")
            }
        }
        #else
        status = "Export unsupported on this platform"
        #endif
    }

    func disconnect() async {
        await runAction(prefix: "disconnect") { [self] in
            await disconnectSession()
        }
    }

    func scenePhaseDidChange(_ phase: ScenePhase) async {
        switch phase {
        case .background:
            await handleBackgroundTransition()
        case .active:
            await handleForegroundRecovery()
        case .inactive:
            break
        @unknown default:
            break
        }
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

    private func handleBackgroundTransition() async {
        guard session != nil else {
            shouldRecoverOnActive = false
            pendingRecoveryDeviceID = nil
            return
        }

        if hasSelectedDevice {
            pendingRecoveryDeviceID = devices[selectedDeviceIndex].id
        }
        shouldRecoverOnActive = true
        appendLog("lifecycle: entering background, disconnecting active BLE session")
        await disconnectSession()
    }

    private func handleForegroundRecovery() async {
        guard shouldRecoverOnActive else { return }
        guard !isBusy else {
            appendLog("lifecycle: skipped recovery because another operation is in progress")
            return
        }

        isBusy = true
        defer {
            isBusy = false
            pendingRecoveryDeviceID = nil
        }
        shouldRecoverOnActive = false

        appendLog("lifecycle: app became active, attempting BLE session recovery")
        do {
            await bootstrap()
            guard let coreKit else { return }

            let discovered = try await coreKit.discoverTrezor(timeoutMs: 4_000)
            devices = discovered
            if let recoveryID = pendingRecoveryDeviceID,
               let matchingIndex = discovered.firstIndex(where: { $0.id == recoveryID })
            {
                selectedDeviceIndex = matchingIndex
            } else if !discovered.isEmpty {
                selectedDeviceIndex = 0
            }

            if hasSelectedDevice {
                try await ensureConnectedSession()
                if let session, sessionState?.canConnect == true {
                    let state = try await session.connectReady(tryToUnlock: true)
                    applySessionState(state, trigger: .connectReady)
                } else {
                    try await refreshSessionState()
                }
                appendLog("lifecycle: recovery complete")
            } else {
                status = "No devices found for recovery"
                appendLog("lifecycle: recovery aborted, no scanned devices")
            }
        } catch {
            handleError(error, prefix: "lifecycleRecovery")
        }
    }

    private func ensureConnectedSession() async throws {
        await bootstrap()
        guard let coreKit else { return }
        guard hasSelectedDevice else {
            status = "Select a device first"
            return
        }
        if session != nil {
            try await refreshSessionState()
            return
        }

        let selected = devices[selectedDeviceIndex]
        session = try await coreKit.connect(device: selected)
        status = "Connected: \(selected.id)"
        appendLog("connected: \(selected.id)")
        startEventStream()
        try await refreshSessionState()
    }

    private func refreshSessionState() async throws {
        guard let session else {
            sessionState = nil
            phaseSummary = "No session"
            return
        }
        let state = try await session.sessionState()
        applySessionState(state, trigger: nil)
    }

    private func applySessionState(_ state: SessionState, trigger: PendingPairingFlow?) {
        sessionState = state
        phaseSummary = describe(state.phase)
        pairingPromptMessage = state.promptMessage ?? ""
        appendLog("session phase: \(phaseSummary)")

        if state.requiresPairingCode {
            if let trigger {
                pendingPairingFlow = trigger
            }
            status = "Pairing required"
            if case .connectReady? = trigger {
                appendLog(
                    "connect requested pairing code: host credentials were not accepted for this handshake"
                )
            }
            return
        }

        switch state.phase {
        case .ready:
            status = "Session ready"
        case .needsSession:
            status = "Paired. Run Connect to create session."
        case .needsConnectionConfirmation:
            status = "Waiting for connection confirmation"
        case .needsHandshake:
            status = "Handshake required"
        case .needsChannel:
            status = "Channel required"
        case .needsPairingCode:
            status = "Pairing code required"
        }
    }

    private func describe(_ phase: SessionPhase) -> String {
        switch phase {
        case .needsChannel:
            return "Needs channel"
        case .needsHandshake:
            return "Needs handshake"
        case .needsPairingCode:
            return "Needs pairing code"
        case .needsConnectionConfirmation:
            return "Needs connection confirmation"
        case .needsSession:
            return "Needs session"
        case .ready:
            return "Ready"
        }
    }

    func chainLabel(_ chain: Chain) -> String {
        switch chain {
        case .ethereum:
            return "ETH"
        case .bitcoin:
            return "BTC"
        case .solana:
            return "SOL"
        }
    }

    private func buildSignRequest(
        chain: Chain,
        session: WalletSession
    ) async throws -> SignTxRequest {
        switch chain {
        case .ethereum:
            let chainId = try parseU64(ethChainId, fieldName: "ETH chain id")
            guard !ethTo.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw InputValidationError(message: "ETH to address is required")
            }
            guard !ethGasLimit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw InputValidationError(message: "ETH gas limit is required")
            }
            guard !ethMaxFeePerGas.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw InputValidationError(message: "ETH max fee per gas is required")
            }
            guard !ethMaxPriorityFee.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw InputValidationError(message: "ETH max priority fee is required")
            }
            return SignTxRequest.ethereum(
                path: resolvedPath(ethSignPathInput, chain: .ethereum),
                to: ethTo.trimmingCharacters(in: .whitespacesAndNewlines),
                value: defaultIfEmpty(ethValue, fallback: "0x0"),
                nonce: defaultIfEmpty(ethNonce, fallback: "0x0"),
                gasLimit: ethGasLimit.trimmingCharacters(in: .whitespacesAndNewlines),
                chainId: chainId,
                data: defaultIfEmpty(ethData, fallback: "0x"),
                maxFeePerGas: ethMaxFeePerGas.trimmingCharacters(in: .whitespacesAndNewlines),
                maxPriorityFee: ethMaxPriorityFee.trimmingCharacters(in: .whitespacesAndNewlines),
                chunkify: ethChunkify
            )
        case .solana:
            let resolvedSolPath = resolvedPath(solSignPathInput, chain: .solana)
            let txHex = sanitizedHex(solSerializedTxHex)
            guard !txHex.isEmpty else {
                throw InputValidationError(message: "SOL tx hex is required")
            }
            return SignTxRequest.solana(
                path: resolvedSolPath,
                serializedTxHex: txHex,
                chunkify: solChunkify
            )
        case .bitcoin:
            let txJson = btcTxJsonInput.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !txJson.isEmpty else {
                throw InputValidationError(message: "BTC tx JSON is required")
            }
            guard let data = txJson.data(using: .utf8),
                  (try? JSONSerialization.jsonObject(with: data)) != nil
            else {
                throw InputValidationError(message: "BTC tx JSON is invalid")
            }
            return SignTxRequest.bitcoin(txJson: txJson)
        }
    }

    private func buildMessageSignRequest(chain: Chain) throws -> SignMessageRequest {
        let payload = messageSignPayload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !payload.isEmpty else {
            throw InputValidationError(message: "Message payload is required")
        }

        switch chain {
        case .ethereum:
            return SignMessageRequest.ethereum(
                path: resolvedPath(messageSignPathInput, chain: .ethereum),
                message: payload,
                isHex: messageSignIsHex,
                chunkify: messageSignChunkify
            )
        case .bitcoin:
            return SignMessageRequest.bitcoin(
                path: resolvedPath(messageSignPathInput, chain: .bitcoin),
                message: payload,
                isHex: messageSignIsHex,
                chunkify: messageSignChunkify
            )
        case .solana:
            throw InputValidationError(message: "Message signing is available for ETH/BTC only")
        }
    }

    private func describeSignResult(_ result: SignTxResult, chain: Chain) -> String {
        switch chain {
        case .ethereum:
            return "v=\(result.v) r=0x\(hex(result.r)) s=0x\(hex(result.s))"
        case .bitcoin, .solana:
            return "signature=0x\(hex(result.r))"
        }
    }

    private func describeMessageSignResult(_ result: SignMessageResult) -> String {
        "address=\(result.address) signature=\(result.signatureFormatted)"
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func defaultPath(for chain: Chain) -> String {
        chain.defaultPath
    }

    private func resolvedPath(_ input: String, chain: Chain) -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? defaultPath(for: chain) : trimmed
    }

    private func sanitizedHex(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
            return String(trimmed.dropFirst(2))
        }
        return trimmed
    }

    private func defaultIfEmpty(_ value: String, fallback: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? fallback : trimmed
    }

    private func parseU64(_ value: String, fieldName: String) throws -> UInt64 {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw InputValidationError(message: "\(fieldName) is required")
        }
        if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
            guard let parsed = UInt64(trimmed.dropFirst(2), radix: 16) else {
                throw InputValidationError(message: "\(fieldName) must be a valid integer")
            }
            return parsed
        }
        guard let parsed = UInt64(trimmed) else {
            throw InputValidationError(message: "\(fieldName) must be a valid integer")
        }
        return parsed
    }

    private func summarizeBitcoinTxJson(_ json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any]
        else {
            return nil
        }
        let inputs = (dictionary["inputs"] as? [Any])?.count ?? 0
        let outputs = (dictionary["outputs"] as? [Any])?.count ?? 0
        let refTxs = (dictionary["ref_txs"] as? [Any])?.count ?? 0
        return "inputs=\(inputs) outputs=\(outputs) ref_txs=\(refTxs)"
    }

    private func copyToClipboard(_ value: String, emptyMessage: String, successLabel: String) {
        guard !value.isEmpty else {
            status = emptyMessage
            return
        }
        #if canImport(AppKit)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        status = "\(successLabel.capitalized) copied"
        appendLog("\(successLabel) copied")
        #elseif canImport(UIKit)
        UIPasteboard.general.string = value
        status = "\(successLabel.capitalized) copied"
        appendLog("\(successLabel) copied")
        #else
        status = "Clipboard unsupported on this platform"
        #endif
    }

    private func disconnectSession() async {
        guard let session else {
            return
        }
        await session.disconnect()
        self.session = nil
        sessionState = nil
        phaseSummary = "No session"
        showPairingAlert = false
        pendingPairingFlow = nil
        pairingPromptMessage = ""
        eventTask?.cancel()
        eventTask = nil
        status = "Disconnected"
        appendLog("disconnected")
    }

    private func clearPairingStorage() throws {
        guard let storagePath else {
            return
        }
        let path = NSString(string: storagePath).expandingTildeInPath
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: path) {
            try fileManager.removeItem(atPath: path)
            appendLog("cleared pairing storage: \(path)")
        }
    }

    private func defaultStoragePath() -> String {
        #if os(iOS)
        let fileManager = FileManager.default
        let baseURL = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let directory = baseURL.appendingPathComponent("hw-core", isDirectory: true)
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("thp-host.json").path
        #else
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.hw-core/thp-host.json"
        #endif
    }

    private func defaultHostName() -> String {
        #if os(iOS)
        UIDevice.current.name
        #else
        Host.current().localizedName ?? "macOS"
        #endif
    }

    private func loadStorageSnapshotSummary(path: String) -> StorageSnapshotSummary? {
        let expandedPath = NSString(string: path).expandingTildeInPath
        guard FileManager.default.fileExists(atPath: expandedPath) else {
            return StorageSnapshotSummary(
                schemaVersion: 0,
                hasStaticKey: false,
                knownCredentialCount: 0
            )
        }
        guard let data = FileManager.default.contents(atPath: expandedPath) else {
            return nil
        }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any]
        else {
            return nil
        }
        let schemaVersion = dictionary["schema_version"] as? Int ?? 0
        let hasStaticKey = dictionary["static_key"] is [Any]
        let knownCredentialCount = (dictionary["known_credentials"] as? [Any])?.count ?? 0
        return StorageSnapshotSummary(
            schemaVersion: schemaVersion,
            hasStaticKey: hasStaticKey,
            knownCredentialCount: knownCredentialCount
        )
    }

    private func runAction(prefix: String, _ operation: @escaping () async throws -> Void) async {
        if isBusy {
            return
        }
        isBusy = true
        defer { isBusy = false }

        do {
            try await operation()
        } catch {
            handleError(error, prefix: prefix)
        }
    }

    private func appendLog(_ line: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let entry = "[\(timestamp)] \(line)"
        logs.append(entry)
        print(entry)
    }

    private func startPairingPrompt(trigger: PendingPairingFlow) async throws {
        guard let session else {
            return
        }

        pendingPairingFlow = trigger
        let prompt = try await session.startPairing()
        pairingPromptMessage = prompt.message
        status = "Pairing code required"
        showPairingAlert = true
        appendLog("pairing prompt: \(prompt.message)")
    }

    private func handleError(_ error: Error, prefix: String) {
        status = "Error: \(prefix)"
        appendLog("\(prefix) failed: \(error.localizedDescription)")
    }
}
