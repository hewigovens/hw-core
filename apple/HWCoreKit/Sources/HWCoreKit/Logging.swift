import Foundation

public protocol WalletLogger: Sendable {
    func log(_ entry: WalletLogEntry)
}

public enum WalletLogLevel: String, Sendable {
    case debug
    case info
    case warning
    case error
}

public struct WalletLogEntry: Sendable {
    public let level: WalletLogLevel
    public let operation: String
    public let message: String
    public let metadata: [String: String]

    public init(level: WalletLogLevel, operation: String, message: String, metadata: [String: String] = [:]) {
        self.level = level
        self.operation = operation
        self.message = message
        self.metadata = metadata
    }
}
