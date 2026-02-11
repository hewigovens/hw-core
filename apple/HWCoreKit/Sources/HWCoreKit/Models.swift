import Foundation
import HWCoreKitBindings

public struct HWCoreConfig: Sendable {
    public var hostName: String
    public var appName: String
    public var storagePath: String?
    public var pairingMethods: [HwPairingMethod]

    public init(
        hostName: String,
        appName: String,
        storagePath: String? = nil,
        pairingMethods: [HwPairingMethod] = [.codeEntry]
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
    public let kind: HwWorkflowEventKind
    public let code: String
    public let message: String

    init(raw: HwWorkflowEvent) {
        kind = raw.kind
        code = raw.code
        message = raw.message
    }
}

public enum SessionHandshakeState: Sendable {
    case ready
    case pairingRequired(HwPairingPrompt)
    case connectionConfirmationRequired(HwPairingPrompt)
}

public struct EthereumAddressResult: Sendable {
    public let address: String
    public let mac: Data?
    public let publicKey: String?
}

public struct EthereumAccessListEntry: Sendable {
    public let address: String
    public let storageKeys: [String]

    public init(address: String, storageKeys: [String] = []) {
        self.address = address
        self.storageKeys = storageKeys
    }
}

public struct EthereumSignRequest: Sendable {
    public let path: String
    public let to: String
    public let value: String
    public let nonce: String
    public let gasLimit: String
    public let chainId: UInt64
    public let data: String
    public let maxFeePerGas: String
    public let maxPriorityFee: String
    public let accessList: [EthereumAccessListEntry]
    public let chunkify: Bool

    public init(
        path: String = "m/44'/60'/0'/0/0",
        to: String,
        value: String = "0x0",
        nonce: String = "0x0",
        gasLimit: String,
        chainId: UInt64,
        data: String = "0x",
        maxFeePerGas: String,
        maxPriorityFee: String,
        accessList: [EthereumAccessListEntry] = [],
        chunkify: Bool = false
    ) {
        self.path = path
        self.to = to
        self.value = value
        self.nonce = nonce
        self.gasLimit = gasLimit
        self.chainId = chainId
        self.data = data
        self.maxFeePerGas = maxFeePerGas
        self.maxPriorityFee = maxPriorityFee
        self.accessList = accessList
        self.chunkify = chunkify
    }
}

public struct EthereumSignResult: Sendable {
    public let v: UInt32
    public let r: Data
    public let s: Data
    public let txHash: Data?
    public let recoveredAddress: String?
}
