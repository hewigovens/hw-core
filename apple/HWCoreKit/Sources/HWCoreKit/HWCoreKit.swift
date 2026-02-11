import Foundation
import HWCoreKitBindings

public final class HWCoreKit: @unchecked Sendable {
    private let manager: BleManagerHandle
    private let config: HWCoreConfig
    private let logger: WalletLogger?

    public static func create(
        config: HWCoreConfig,
        logger: WalletLogger? = nil
    ) async throws -> HWCoreKit {
        do {
            try validateBluetoothUsageDescription()
            let manager = try await BleManagerHandle()
            return HWCoreKit(manager: manager, config: config, logger: logger)
        } catch {
            throw mapError(error)
        }
    }

    public init(manager: BleManagerHandle, config: HWCoreConfig, logger: WalletLogger? = nil) {
        self.manager = manager
        self.config = config
        self.logger = logger
    }

    public func discoverTrezor(timeoutMs: UInt64 = 8_000) async throws -> [WalletDevice] {
        log(
            level: .info,
            operation: "discoverTrezor",
            message: "Scanning for Trezor devices",
            metadata: ["timeout_ms": "\(timeoutMs)"]
        )

        do {
            let discovered = try await manager.discoverTrezor(durationMs: timeoutMs)
            return discovered.map(WalletDevice.init(raw:))
        } catch {
            throw mapError(error)
        }
    }

    public func connect(device: WalletDevice) async throws -> WalletSession {
        do {
            let session = try await device.raw.connect()
            let workflow = try await session.intoWorkflowWithStorage(
                config: makeHostConfig(),
                storagePath: config.storagePath
            )
            log(
                level: .info,
                operation: "connect",
                message: "Connected to device",
                metadata: ["device_id": redacted(device.id)]
            )
            return WalletSession(workflow: workflow, logger: logger)
        } catch {
            throw mapError(error)
        }
    }

    private func makeHostConfig() -> HwHostConfig {
        var hostConfig = hostConfigNew(hostName: config.hostName, appName: config.appName)
        hostConfig.pairingMethods = config.pairingMethods
        return hostConfig
    }

    private func log(level: WalletLogLevel, operation: String, message: String, metadata: [String: String] = [:]) {
        logger?.log(WalletLogEntry(level: level, operation: operation, message: message, metadata: metadata))
    }
}
