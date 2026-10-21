import Foundation
import HWCoreFFI

public struct HWCoreConfig: Sendable {
    public var hostName: String
    public var appName: String
    public var storagePath: String?
    /// App-owned store for the pairing snapshot (e.g. the Keychain); takes precedence over `storagePath`.
    public var hostStorage: HostStorage?
    public var pairingMethods: [PairingMethod]
    public var sessionRetryPolicy: SessionRetryPolicy

    public init(
        hostName: String,
        appName: String,
        storagePath: String? = nil,
        hostStorage: HostStorage? = nil,
        pairingMethods: [PairingMethod] = [.codeEntry],
        sessionRetryPolicy: SessionRetryPolicy = sessionRetryPolicyDefault()
    ) {
        self.hostName = hostName
        self.appName = appName
        self.storagePath = storagePath
        self.hostStorage = hostStorage
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
    /// The prompt the device is showing; set only for `.buttonRequest` events.
    public let buttonRequest: ButtonRequest?

    init(raw: WorkflowEvent) {
        kind = raw.kind
        code = raw.code
        message = raw.message
        buttonRequest = raw.buttonRequest
    }
}

// Request and state models used in HWCoreKit's public API, so apps need only `import HWCoreKit`.
public typealias BitcoinTxInput = HWCoreFFI.BitcoinTxInput
public typealias BitcoinTxOutput = HWCoreFFI.BitcoinTxOutput
public typealias BitcoinRefTx = HWCoreFFI.BitcoinRefTx
public typealias BitcoinRefTxInput = HWCoreFFI.BitcoinRefTxInput
public typealias BitcoinRefTxOutput = HWCoreFFI.BitcoinRefTxOutput
public typealias BitcoinMultisig = HWCoreFFI.BitcoinMultisig
public typealias BitcoinMultisigPubkey = HWCoreFFI.BitcoinMultisigPubkey
public typealias BitcoinMultisigPubkeysOrder = HWCoreFFI.BitcoinMultisigPubkeysOrder
public typealias BtcInputScriptType = HWCoreFFI.BtcInputScriptType
public typealias BtcOutputScriptType = HWCoreFFI.BtcOutputScriptType
public typealias SolanaTxAdditionalInfo = HWCoreFFI.SolanaTxAdditionalInfo
public typealias SolanaTxTokenAccountInfo = HWCoreFFI.SolanaTxTokenAccountInfo
public typealias SignTypedDataRequest = HWCoreFFI.SignTypedDataRequest
public typealias SignTypedDataResult = HWCoreFFI.SignTypedDataResult
public typealias GetAddressRequest = HWCoreFFI.GetAddressRequest
public typealias PairingMethod = HWCoreFFI.PairingMethod
public typealias PairingPrompt = HWCoreFFI.PairingPrompt
public typealias PairingProgress = HWCoreFFI.PairingProgress
public typealias PairingProgressKind = HWCoreFFI.PairingProgressKind
public typealias SessionState = HWCoreFFI.SessionState
public typealias SessionPhase = HWCoreFFI.SessionPhase
public typealias WorkflowEventKind = HWCoreFFI.WorkflowEventKind
public typealias HostConfig = HWCoreFFI.HostConfig
public typealias KnownCredential = HWCoreFFI.KnownCredential
public typealias BleDeviceInfo = HWCoreFFI.BleDeviceInfo
public typealias HwCoreError = HWCoreFFI.HwCoreError
public typealias HostStorage = HWCoreFFI.HostStorage
public typealias HostStorageError = HWCoreFFI.HostStorageError
public typealias ButtonRequest = HWCoreFFI.ButtonRequest
public typealias ButtonRequestCode = HWCoreFFI.ButtonRequestCode
public typealias DeviceFeatures = HWCoreFFI.DeviceFeatures
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
public typealias BitcoinSignTxRequest = HWCoreFFI.BitcoinSignTxRequest
public typealias SignTxRequest = HWCoreFFI.SignTxRequest
public typealias SignTxResult = HWCoreFFI.SignTxResult
public typealias EthereumDefinitions = HWCoreFFI.EthereumDefinitions
public typealias EthereumTokenDefinition = HWCoreFFI.EthereumTokenDefinition
public typealias EthereumDisplayFormatDefinition = HWCoreFFI.EthereumDisplayFormatDefinition
public typealias EthereumDefinitionsSource = HWCoreFFI.EthereumDefinitionsSource

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
        chunkify: Bool = false,
        definitions: EthereumDefinitions? = nil
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
            chunkify: chunkify,
            ethDefinitions: definitions
        )
    }

    static func solana(
        path: String = Chain.solana.defaultPath,
        serializedTxHex: String,
        chunkify: Bool = false,
        additionalInfo: SolanaTxAdditionalInfo? = nil
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
            chunkify: chunkify,
            solanaAdditionalInfo: additionalInfo
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
        chunkify: Bool = false,
        encodedNetwork: Data? = nil
    ) -> SignMessageRequest {
        SignMessageRequest(
            chain: .ethereum,
            path: path,
            message: message,
            isHex: isHex,
            chunkify: chunkify,
            encodedNetwork: encodedNetwork
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

    static func solana(
        path: String = Chain.solana.defaultPath,
        message: String,
        isHex: Bool = false,
        chunkify: Bool = false,
        signers: [String] = []
    ) -> SignMessageRequest {
        SignMessageRequest(
            chain: .solana,
            path: path,
            message: message,
            isHex: isHex,
            chunkify: chunkify,
            signers: signers
        )
    }
}
