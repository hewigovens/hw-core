import Foundation
import HWCoreFFI

public enum WalletVendor: String, CaseIterable, Sendable {
    case trezor = "Trezor Safe 7"
    case ledgerStax = "Ledger Stax"
    case ledgerNanoX = "Ledger Nano X"
    case ledgerFlex = "Ledger Flex"

    public var isLedger: Bool { self != .trezor }
    public var supportedChains: [Chain] { isLedger ? [.ethereum, .solana] : [.ethereum, .bitcoin, .solana] }
    var ledgerModel: LedgerModel? {
        switch self {
        case .trezor: nil
        case .ledgerStax: .stax
        case .ledgerNanoX: .nanoX
        case .ledgerFlex: .flex
        }
    }
}
