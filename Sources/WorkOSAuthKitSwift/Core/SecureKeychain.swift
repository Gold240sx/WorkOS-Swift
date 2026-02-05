import Foundation
import Security
import LocalAuthentication

/// Secure keychain storage with optional biometric protection.
public enum SecureKeychain {

    // MARK: - Standard Storage

    /// Save a string value to keychain.
    public static func save(_ key: String, _ value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw AuthError.keychainError("Failed to encode value")
        }
        try save(key, data: data)
    }

    /// Save data to keychain.
    public static func save(_ key: String, data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]

        // Delete existing item first
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AuthError.keychainError("Keychain save failed: \(status)")
        }
    }

    /// Read a string value from keychain.
    public static func read(_ key: String) -> String? {
        guard let data = readData(key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Read data from keychain.
    public static func readData(_ key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]

        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    /// Delete an item from keychain.
    public static func delete(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Biometric Protected Storage

    /// Save data with biometric protection.
    public static func saveProtected(_ key: String, data: Data) throws {
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            nil
        ) else {
            throw AuthError.keychainError("Failed to create access control")
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]

        // Delete existing item first
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AuthError.keychainError("Protected keychain save failed: \(status)")
        }
    }

    /// Read biometric-protected data.
    /// Returns nil if biometric authentication fails.
    public static func readProtected(_ key: String) async throws -> Data {
        let context = LAContext()
        context.localizedReason = "Unlock your session"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        return try await withCheckedThrowingContinuation { continuation in
            var item: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            if status == errSecSuccess, let data = item as? Data {
                continuation.resume(returning: data)
            } else {
                continuation.resume(throwing: AuthError.biometricFailed("Authentication failed: \(status)"))
            }
        }
    }

    // MARK: - Tokens Storage

    private static let tokensKey = "workos_auth_tokens"

    /// Save authentication tokens.
    public static func saveTokens(_ tokens: AuthTokens) throws {
        let data = try JSONEncoder().encode(tokens)
        try save(tokensKey, data: data)
    }

    /// Load authentication tokens.
    public static func loadTokens() -> AuthTokens? {
        guard let data = readData(tokensKey) else { return nil }
        return try? JSONDecoder().decode(AuthTokens.self, from: data)
    }

    /// Save tokens with biometric protection.
    public static func saveTokensProtected(_ tokens: AuthTokens) throws {
        let data = try JSONEncoder().encode(tokens)
        try saveProtected(tokensKey, data: data)
    }

    /// Load tokens with biometric authentication.
    public static func loadTokensProtected() async throws -> AuthTokens {
        let data = try await readProtected(tokensKey)
        return try JSONDecoder().decode(AuthTokens.self, from: data)
    }

    /// Clear all authentication data.
    public static func clearAuth() {
        delete(tokensKey)
        delete("offline_session")
    }
}
