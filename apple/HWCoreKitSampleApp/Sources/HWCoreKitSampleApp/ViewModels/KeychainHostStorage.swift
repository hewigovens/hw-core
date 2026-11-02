import Foundation
import HWCoreKit
import Security

/// Keeps the pairing snapshot, which holds the host's THP private key, in the Keychain.
final class KeychainHostStorage: HostStorage, @unchecked Sendable {
    // Same item as hw-cli, so the sample and the CLI keep sharing one host identity on macOS.
    private let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "hw-core",
        kSecAttrAccount as String: "thp-host",
    ]

    func load() throws -> Data? {
        var item: CFTypeRef?
        var lookup = query
        lookup[kSecReturnData as String] = true
        switch SecItemCopyMatching(lookup as CFDictionary, &item) {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound: return nil
        case let status: throw HostStorageError.Failed(reason: "Keychain read failed: \(status)")
        }
    }

    func persist(snapshot: Data) throws {
        let update = [kSecValueData as String: snapshot] as CFDictionary
        var status = SecItemUpdate(query as CFDictionary, update)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = snapshot
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw HostStorageError.Failed(reason: "Keychain write failed: \(status)")
        }
    }

    func clear() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw HostStorageError.Failed(reason: "Keychain delete failed: \(status)")
        }
    }

    /// Moves a snapshot left by a file-based version into the Keychain and deletes the file.
    /// Returns whether a file was removed.
    func importLegacyFile(atPath path: String) throws -> Bool {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: path) else {
            return false
        }
        if try load() == nil, let snapshot = fileManager.contents(atPath: path) {
            try persist(snapshot: snapshot)
        }
        try fileManager.removeItem(atPath: path)
        return true
    }
}
