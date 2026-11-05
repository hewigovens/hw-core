import Foundation
import HWCoreFFI

public final class WalletSession: @unchecked Sendable {
    private enum Backend {
        case trezor(BleWorkflowHandle)
        case ledger(LedgerSessionHandle)
    }
    private let backend: Backend
    private let logger: WalletLogger?
    private let retryPolicy: SessionRetryPolicy

    init(
        workflow: BleWorkflowHandle,
        logger: WalletLogger?,
        retryPolicy: SessionRetryPolicy
    ) {
        self.backend = .trezor(workflow)
        self.logger = logger
        self.retryPolicy = retryPolicy
    }

    init(ledger: LedgerSessionHandle, logger: WalletLogger?, retryPolicy: SessionRetryPolicy) {
        self.backend = .ledger(ledger)
        self.logger = logger
        self.retryPolicy = retryPolicy
    }

    private func trezorWorkflow() throws -> BleWorkflowHandle {
        guard case .trezor(let workflow) = backend else {
            throw HwCoreError.Unsupported(message: "This operation is specific to Trezor")
        }
        return workflow
    }

    public func events(timeoutMs: UInt64 = 500) -> AsyncStream<WalletEvent> {
        if case .ledger = backend { return AsyncStream { $0.finish() } }
        return AsyncStream { continuation in
            let task = Task {
                while !Task.isCancelled {
                    do {
                        if let rawEvent = try await self.trezorWorkflow().nextEvent(timeoutMs: timeoutMs) {
                            continuation.yield(WalletEvent(raw: rawEvent))
                        }
                    } catch {
                        continuation.finish()
                        return
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    public func sessionState(timeout: TimeInterval? = nil) async throws -> SessionState {
        do {
            return try await withTimeout(seconds: timeout, operation: "sessionState") {
                if case .ledger(let ledger) = self.backend {
                    _ = try await ledger.appInfo()
                    return SessionState(
                        phase: .ready, canPairOnly: false, canConnect: false,
                        canGetAddress: true, canSignTx: true,
                        requiresPairingCode: false, promptMessage: nil
                    )
                }
                return try await self.trezorWorkflow().sessionState()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func pairOnly(
        tryToUnlock: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> SessionState {
        do {
            return try await withTimeout(seconds: timeout, operation: "pairOnly") {
                try await self.trezorWorkflow().pairOnlyWithPolicy(
                    tryToUnlock: tryToUnlock,
                    retryPolicy: self.retryPolicy
                )
            }
        } catch {
            throw mapError(error)
        }
    }

    public func connectReady(
        tryToUnlock: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> SessionState {
        if case .ledger = backend { return try await sessionState(timeout: timeout) }
        do {
            return try await withTimeout(seconds: timeout, operation: "connectReady") {
                try await self.trezorWorkflow().connectReadyWithPolicy(
                    tryToUnlock: tryToUnlock,
                    retryPolicy: self.retryPolicy
                )
            }
        } catch {
            throw mapError(error)
        }
    }

    public func prepareChannelAndHandshake(
        tryToUnlock: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> SessionHandshakeState {
        do {
            return try await withTimeout(seconds: timeout, operation: "prepareChannelAndHandshake") {
                try await self.trezorWorkflow().prepareChannelAndHandshake(tryToUnlock: tryToUnlock)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func startPairing(timeout: TimeInterval? = nil) async throws -> PairingPrompt {
        do {
            return try await withTimeout(seconds: timeout, operation: "startPairing") {
                try await self.trezorWorkflow().pairingStart()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func submitPairingCode(_ code: String, timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "submitPairingCode") {
                try await self.trezorWorkflow().pairingSubmitCode(code: code)
            }
        } catch {
            throw mapError(error)
        }
    }

    /// Switches a started pairing to QR code or NFC; for NFC, hand `nfcData` to the device.
    public func selectPairingMethod(_ method: PairingMethod, timeout: TimeInterval? = nil) async throws -> PairingPrompt {
        do {
            return try await withTimeout(seconds: timeout, operation: "selectPairingMethod") {
                try await self.trezorWorkflow().pairingSelectMethod(method: method)
            }
        } catch {
            throw mapError(error)
        }
    }

    /// Completes QR code pairing with the hex data scanned from the Trezor screen.
    public func submitPairingQrTag(_ tag: String, timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "submitPairingQrTag") {
                try await self.trezorWorkflow().pairingSubmitQrTag(tag: tag)
            }
        } catch {
            throw mapError(error)
        }
    }

    /// Completes NFC pairing with the hex tag read from the Trezor over NFC.
    public func submitPairingNfcTag(_ tag: String, timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "submitPairingNfcTag") {
                try await self.trezorWorkflow().pairingSubmitNfcTag(tag: tag)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func confirmPairedConnection(timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "confirmPairedConnection") {
                try await self.trezorWorkflow().pairingConfirmConnection()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func createWalletSession(
        passphrase: String? = nil,
        onDevice: Bool = false,
        deriveCardano: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws {
        do {
            _ = try await withTimeout(seconds: timeout, operation: "createWalletSession") {
                try await self.trezorWorkflow().createSession(
                    passphrase: passphrase,
                    onDevice: onDevice,
                    deriveCardano: deriveCardano
                )
                return true
            }
        } catch {
            throw mapError(error)
        }
    }

    public func getAddress(
        chain: Chain = .ethereum,
        path: String? = nil,
        showOnDevice: Bool = true,
        includePublicKey: Bool = false,
        chunkify: Bool = false,
        encodedNetwork: Data? = nil,
        timeout: TimeInterval? = nil
    ) async throws -> AddressResult {
        do {
            let request = GetAddressRequest(
                chain: chain,
                path: path ?? chainConfig(chain: chain).defaultPath,
                showOnDevice: showOnDevice,
                includePublicKey: includePublicKey,
                chunkify: chunkify,
                encodedNetwork: encodedNetwork
            )
            return try await withTimeout(seconds: timeout, operation: "getAddress") {
                if case .ledger(let ledger) = self.backend {
                    return try await ledger.getAddress(request: request)
                }
                return try await self.trezorWorkflow().getAddress(request: request)
            }
        } catch {
            throw mapError(error)
        }
    }

    /// Device id, label, model, firmware version and passphrase settings.
    public func getFeatures(timeout: TimeInterval? = nil) async throws -> DeviceFeatures {
        do {
            return try await withTimeout(seconds: timeout, operation: "getFeatures") {
                try await self.trezorWorkflow().getFeatures()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func getNonce(timeout: TimeInterval? = nil) async throws -> String {
        do {
            return try await withTimeout(seconds: timeout, operation: "getNonce") {
                try await self.trezorWorkflow().getNonce()
            }
        } catch {
            throw mapError(error)
        }
    }

    /// Signs a Bitcoin transaction from typed inputs, outputs and reference transactions.
    public func signBitcoinTx(
        _ request: BitcoinSignTxRequest,
        timeout: TimeInterval? = nil
    ) async throws -> SignTxResult {
        do {
            return try await withTimeout(seconds: timeout, operation: "signBitcoinTx") {
                try await self.trezorWorkflow().signBitcoinTx(request: request)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func signTx(
        _ request: SignTxRequest,
        timeout: TimeInterval? = nil
    ) async throws -> SignTxResult {
        do {
            return try await withTimeout(seconds: timeout, operation: "signTx") {
                if case .ledger(let ledger) = self.backend {
                    return try await ledger.signTx(request: request)
                }
                return try await self.trezorWorkflow().signTx(request: request)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func signMessage(
        _ request: SignMessageRequest,
        timeout: TimeInterval? = nil
    ) async throws -> SignMessageResult {
        do {
            return try await withTimeout(seconds: timeout, operation: "signMessage") {
                if case .ledger(let ledger) = self.backend {
                    return try await ledger.signMessage(request: request)
                }
                return try await self.trezorWorkflow().signMessage(request: request)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func signTypedData(_ request: SignTypedDataRequest, timeout: TimeInterval? = nil) async throws -> SignTypedDataResult {
        do {
            return try await withTimeout(seconds: timeout, operation: "signTypedData") {
                if case .ledger(let ledger) = self.backend {
                    return try await ledger.signTypedData(request: request)
                }
                return try await self.trezorWorkflow().signTypedData(request: request)
            }
        } catch { throw mapError(error) }
    }

    /// Cancels the running request. For Ledger, reject any remaining device prompt
    /// and disconnect before reconnecting; cancellation cannot dismiss its screen.
    public func cancel() {
        switch backend {
        case .trezor(let workflow): workflow.cancel()
        case .ledger(let ledger): ledger.cancel()
        }
    }

    public func disconnect(timeout: TimeInterval? = 5) async {
        if case .ledger(let ledger) = backend {
            try? await withTimeout(seconds: timeout, operation: "disconnect") { try await ledger.disconnect() }
            return
        }
        do {
            _ = try await withTimeout(seconds: timeout, operation: "disconnect") {
                try await self.trezorWorkflow().abort()
                return true
            }
        } catch {
            log(level: .warning, operation: "disconnect", message: "Ignoring disconnect failure")
        }
    }

    private func log(level: WalletLogLevel, operation: String, message: String, metadata: [String: String] = [:]) {
        logger?.log(WalletLogEntry(level: level, operation: operation, message: message, metadata: metadata))
    }
}
