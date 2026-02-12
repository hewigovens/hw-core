import Foundation
import HWCoreFFI

public struct HWCoreConfig: Sendable {
    public var hostName: String
    public var appName: String
    public var storagePath: String?
    public var pairingMethods: [PairingMethod]

    public init(
        hostName: String,
        appName: String,
        storagePath: String? = nil,
        pairingMethods: [PairingMethod] = [.codeEntry]
    ) {
        self.hostName = hostName
        self.appName = appName
        self.storagePath = storagePath
        self.pairingMethods = pairingMethods
    }
}

public final class WalletDevice: @unchecked Sendable {
    public let id: String
    public let name: String?
    public let rssi: Int32?

    let raw: BleDiscoveredDevice

    init(raw: BleDiscoveredDevice) {
        let info = raw.info()
        self.id = info.id
        self.name = info.name
        self.rssi = info.rssi
        self.raw = raw
    }
}

public struct WalletEvent: Sendable {
    public let kind: WorkflowEventKind
    public let code: String
    public let message: String

    init(raw: WorkflowEvent) {
        kind = raw.kind
        code = raw.code
        message = raw.message
    }
}

public typealias SessionHandshakeState = HWCoreFFI.SessionHandshakeState
public typealias AddressResult = HWCoreFFI.AddressResult
public typealias AccessListEntry = HWCoreFFI.AccessListEntry
public typealias SignTxRequest = HWCoreFFI.SignTxRequest
public typealias SignTxResult = HWCoreFFI.SignTxResult

public extension SignTxRequest {
    static func ethereum(
        path: String = "m/44'/60'/0'/0/0",
        to: String,
        value: String = "0x0",
        nonce: String = "0x0",
        gasLimit: String,
        chainId: UInt64,
        data: String = "0x",
        maxFeePerGas: String,
        maxPriorityFee: String,
        accessList: [AccessListEntry] = [],
        chunkify: Bool = false
    ) -> SignTxRequest {
        SignTxRequest(
            chain: .ethereum,
            path: path,
            to: to,
            value: value,
            nonce: nonce,
            gasLimit: gasLimit,
            chainId: chainId,
            data: data,
            maxFeePerGas: maxFeePerGas,
            maxPriorityFee: maxPriorityFee,
            accessList: accessList,
            chunkify: chunkify
        )
    }
}
