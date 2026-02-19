import Foundation
import HWCoreFFI

public struct HWCoreConfig: Sendable {
    public var hostName: String
    public var appName: String
    public var storagePath: String?
    public var pairingMethods: [PairingMethod]
    public var sessionRetryPolicy: SessionRetryPolicy

    public init(
        hostName: String,
        appName: String,
        storagePath: String? = nil,
        pairingMethods: [PairingMethod] = [.codeEntry],
        sessionRetryPolicy: SessionRetryPolicy = sessionRetryPolicyDefault()
    ) {
        self.hostName = hostName
        self.appName = appName
        self.storagePath = storagePath
        self.pairingMethods = pairingMethods
        self.sessionRetryPolicy = sessionRetryPolicy
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
public typealias Chain = HWCoreFFI.Chain
public typealias ChainConfig = HWCoreFFI.ChainConfig
public typealias SessionRetryPolicy = HWCoreFFI.SessionRetryPolicy
public typealias AddressResult = HWCoreFFI.AddressResult
public typealias AccessListEntry = HWCoreFFI.AccessListEntry
public typealias SignatureEncoding = HWCoreFFI.SignatureEncoding
public typealias MessageSignatureEncoding = SignatureEncoding
public typealias SignMessageRequest = HWCoreFFI.SignMessageRequest
public typealias SignMessageResult = HWCoreFFI.SignMessageResult
public typealias SignTxRequest = HWCoreFFI.SignTxRequest
public typealias SignTxResult = HWCoreFFI.SignTxResult

public extension Chain {
    var defaultPath: String {
        HWCoreFFI.chainConfig(chain: self).defaultPath
    }
}

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

    static func solana(
        path: String = Chain.solana.defaultPath,
        serializedTxHex: String,
        chunkify: Bool = false
    ) -> SignTxRequest {
        SignTxRequest(
            chain: .solana,
            path: path,
            to: "",
            value: "0x0",
            nonce: "0x0",
            gasLimit: "0x0",
            chainId: 0,
            data: serializedTxHex,
            maxFeePerGas: "0x0",
            maxPriorityFee: "0x0",
            accessList: [],
            chunkify: chunkify
        )
    }

    static func bitcoin(
        txJson: String
    ) -> SignTxRequest {
        SignTxRequest(
            chain: .bitcoin,
            path: "",
            to: "",
            value: "0x0",
            nonce: "0x0",
            gasLimit: "0x0",
            chainId: 0,
            data: txJson,
            maxFeePerGas: "0x0",
            maxPriorityFee: "0x0",
            accessList: [],
            chunkify: false
        )
    }
}

public extension SignMessageRequest {
    static func ethereum(
        path: String = Chain.ethereum.defaultPath,
        message: String,
        isHex: Bool = false,
        chunkify: Bool = false
    ) -> SignMessageRequest {
        SignMessageRequest(
            chain: .ethereum,
            path: path,
            message: message,
            isHex: isHex,
            chunkify: chunkify
        )
    }

    static func bitcoin(
        path: String = Chain.bitcoin.defaultPath,
        message: String,
        isHex: Bool = false,
        chunkify: Bool = false
    ) -> SignMessageRequest {
        SignMessageRequest(
            chain: .bitcoin,
            path: path,
            message: message,
            isHex: isHex,
            chunkify: chunkify
        )
    }
}
