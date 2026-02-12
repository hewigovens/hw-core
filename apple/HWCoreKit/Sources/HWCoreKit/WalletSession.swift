import Foundation
import HWCoreFFI

public final class WalletSession: @unchecked Sendable {
    private let workflow: BleWorkflowHandle
    private let logger: WalletLogger?

    init(workflow: BleWorkflowHandle, logger: WalletLogger?) {
        self.workflow = workflow
        self.logger = logger
    }

    public func events(timeoutMs: UInt64 = 500) -> AsyncStream<WalletEvent> {
        AsyncStream { continuation in
            let task = Task {
                while !Task.isCancelled {
                    do {
                        if let rawEvent = try await workflow.nextEvent(timeoutMs: timeoutMs) {
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
                try await self.workflow.sessionState()
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
                try await self.workflow.pairOnly(tryToUnlock: tryToUnlock)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func connectReady(
        tryToUnlock: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> SessionState {
        do {
            return try await withTimeout(seconds: timeout, operation: "connectReady") {
                try await self.workflow.connectReady(tryToUnlock: tryToUnlock)
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
                try await self.workflow.prepareChannelAndHandshake(tryToUnlock: tryToUnlock)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func startPairing(timeout: TimeInterval? = nil) async throws -> PairingPrompt {
        do {
            return try await withTimeout(seconds: timeout, operation: "startPairing") {
                try await self.workflow.pairingStart()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func submitPairingCode(_ code: String, timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "submitPairingCode") {
                try await self.workflow.pairingSubmitCode(code: code)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func confirmPairedConnection(timeout: TimeInterval? = nil) async throws -> PairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "confirmPairedConnection") {
                try await self.workflow.pairingConfirmConnection()
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
                try await self.workflow.createSession(
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
        path: String = "m/44'/60'/0'/0/0",
        showOnDevice: Bool = false,
        includePublicKey: Bool = false,
        chunkify: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> AddressResult {
        do {
            return try await withTimeout(seconds: timeout, operation: "getAddress") {
                try await self.workflow.getAddress(
                    request: GetAddressRequest(
                        chain: chain,
                        path: path,
                        showOnDevice: showOnDevice,
                        includePublicKey: includePublicKey,
                        chunkify: chunkify
                    )
                )
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
                try await self.workflow.signTx(request: request)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func disconnect(timeout: TimeInterval? = 5) async {
        do {
            _ = try await withTimeout(seconds: timeout, operation: "disconnect") {
                try await self.workflow.abort()
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
