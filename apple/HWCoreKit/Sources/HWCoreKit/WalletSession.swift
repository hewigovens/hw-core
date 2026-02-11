import Foundation
import HWCoreKitBindings

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

    public func prepareChannelAndHandshake(
        tryToUnlock: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> SessionHandshakeState {
        do {
            return try await withTimeout(seconds: timeout, operation: "prepareChannelAndHandshake") {
                _ = try await self.workflow.createChannel()
                try await self.workflow.handshake(tryToUnlock: tryToUnlock)
                let state = await self.workflow.state()

                switch state.phase {
                case .paired:
                    return .ready
                case .pairing:
                    let prompt = try await self.workflow.pairingStart()
                    if prompt.requiresConnectionConfirmation {
                        return .connectionConfirmationRequired(prompt)
                    }
                    return .pairingRequired(prompt)
                case .handshake:
                    throw HWCoreKitError.workflow("unexpected handshake phase")
                }
            }
        } catch {
            throw mapError(error)
        }
    }

    public func startPairing(timeout: TimeInterval? = nil) async throws -> HwPairingPrompt {
        do {
            return try await withTimeout(seconds: timeout, operation: "startPairing") {
                try await self.workflow.pairingStart()
            }
        } catch {
            throw mapError(error)
        }
    }

    public func submitPairingCode(_ code: String, timeout: TimeInterval? = nil) async throws -> HwPairingProgress {
        do {
            return try await withTimeout(seconds: timeout, operation: "submitPairingCode") {
                try await self.workflow.pairingSubmitCode(code: code)
            }
        } catch {
            throw mapError(error)
        }
    }

    public func confirmPairedConnection(timeout: TimeInterval? = nil) async throws -> HwPairingProgress {
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

    public func getEthereumAddress(
        path: String = "m/44'/60'/0'/0/0",
        showOnDevice: Bool = false,
        includePublicKey: Bool = false,
        chunkify: Bool = false,
        timeout: TimeInterval? = nil
    ) async throws -> EthereumAddressResult {
        do {
            let result = try await withTimeout(seconds: timeout, operation: "getEthereumAddress") {
                try await self.workflow.getAddress(
                    request: HwGetAddressRequest(
                        chain: .ethereum,
                        path: path,
                        showOnDevice: showOnDevice,
                        includePublicKey: includePublicKey,
                        chunkify: chunkify
                    )
                )
            }

            return EthereumAddressResult(
                address: result.address,
                mac: result.mac,
                publicKey: result.publicKey
            )
        } catch {
            throw mapError(error)
        }
    }

    public func signEthereumTx(
        _ request: EthereumSignRequest,
        timeout: TimeInterval? = nil
    ) async throws -> EthereumSignResult {
        do {
            let ffiRequest = HwSignEthTxRequest(
                path: request.path,
                to: request.to,
                value: request.value,
                nonce: request.nonce,
                gasLimit: request.gasLimit,
                chainId: request.chainId,
                data: request.data,
                maxFeePerGas: request.maxFeePerGas,
                maxPriorityFee: request.maxPriorityFee,
                accessList: request.accessList.map {
                    HwEthAccessListEntry(address: $0.address, storageKeys: $0.storageKeys)
                },
                chunkify: request.chunkify
            )

            let result = try await withTimeout(seconds: timeout, operation: "signEthereumTx") {
                try await self.workflow.signEthTx(request: ffiRequest)
            }

            return EthereumSignResult(
                v: result.v,
                r: result.r,
                s: result.s,
                txHash: result.txHash,
                recoveredAddress: result.recoveredAddress
            )
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
