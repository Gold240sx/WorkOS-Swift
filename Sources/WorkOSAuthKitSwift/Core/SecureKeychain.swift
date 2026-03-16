import Foundation
import Security
import LocalAuthentication

/// Secure keychain storage with optional biometric protection.
public enum SecureKeychain {

    // MARK: - Service Identifier

    /// Service identifier for keychain items (required for sandboxed apps)
    private static let serviceIdentifier = "com.michaelMartell.DevSpacePro.WorkOSAuth"

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
        // First, delete any existing item
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key
        ]
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        WorkOSLogger.log("[SecureKeychain] Delete existing '\(key)' status: \(deleteStatus)")

        // Now add the new item
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        WorkOSLogger.log("[SecureKeychain] Save '\(key)' status: \(status) (success=\(status == errSecSuccess))")
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
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]

        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        WorkOSLogger.log("[SecureKeychain] Read '\(key)' status: \(status) (success=\(status == errSecSuccess), found=\(item != nil))")

        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    /// Delete an item from keychain.
    public static func delete(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        WorkOSLogger.log("[SecureKeychain] Delete '\(key)' status: \(status)")
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

        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        WorkOSLogger.log("[SecureKeychain] SaveProtected '\(key)' status: \(status)")
        guard status == errSecSuccess else {
            throw AuthError.keychainError("Protected keychain save failed: \(status)")
        }
    }

    /// Read biometric-protected data.
    public static func readProtected(_ key: String) async throws -> Data {
        let context = LAContext()
        context.localizedReason = "Unlock your session"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]

        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        WorkOSLogger.log("[SecureKeychain] ReadProtected '\(key)' status: \(status)")

        if status == errSecSuccess, let data = item as? Data {
            return data
        }

        if status == errSecUserCanceled {
            throw AuthError.biometricFailed("Authentication was cancelled")
        }

        if status == errSecAuthFailed {
            throw AuthError.biometricFailed("Biometric authentication failed")
        }

        if status == errSecItemNotFound {
            throw AuthError.biometricFailed("Biometric unlock is not enabled")
        }

        throw AuthError.keychainError("Protected keychain read failed: \(status)")
    }

    // MARK: - Tokens Storage

    private static let tokensKey = "workos_auth_tokens"
    private static let biometricTokensKey = "workos_auth_tokens_biometric"

    /// Save authentication tokens.
    public static func saveTokens(_ tokens: AuthTokens) throws {
        let data = try JSONEncoder().encode(tokens)
        try save(tokensKey, data: data)
        WorkOSLogger.log("[SecureKeychain] Tokens saved successfully")
    }

    /// Load authentication tokens.
    /// Also attempts to migrate tokens stored without service identifier.
    public static func loadTokens() -> AuthTokens? {
        // First, try to read with the service identifier (new format)
        if let data = readData(tokensKey) {
            WorkOSLogger.log("[SecureKeychain] Found tokens with service identifier")
            return try? JSONDecoder().decode(AuthTokens.self, from: data)
        }

        // Migration: Try to read tokens stored without service identifier (old format)
        WorkOSLogger.log("[SecureKeychain] Checking for legacy tokens without service identifier...")
        let legacyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tokensKey,
            kSecReturnData as String: true
        ]

        var item: AnyObject?
        let status = SecItemCopyMatching(legacyQuery as CFDictionary, &item)
        WorkOSLogger.log("[SecureKeychain] Legacy token read status: \(status)")

        if status == errSecSuccess, let data = item as? Data,
           let tokens = try? JSONDecoder().decode(AuthTokens.self, from: data) {
            WorkOSLogger.log("[SecureKeychain] Found legacy tokens - migrating to new format")

            // Migrate: save with new format and delete old
            do {
                try saveTokens(tokens)
                // Delete the old format
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: tokensKey
                ]
                SecItemDelete(deleteQuery as CFDictionary)
                WorkOSLogger.log("[SecureKeychain] Legacy tokens migrated successfully")
            } catch {
                WorkOSLogger.log("[SecureKeychain] Migration failed: \(error)")
            }

            return tokens
        }

        WorkOSLogger.log("[SecureKeychain] No tokens found in any format")
        return nil
    }

    /// Save tokens with biometric protection.
    public static func saveTokensProtected(_ tokens: AuthTokens) throws {
        let data = try JSONEncoder().encode(tokens)
        try saveProtected(biometricTokensKey, data: data)
    }

    /// Load tokens with biometric authentication.
    public static func loadTokensProtected() async throws -> AuthTokens {
        // Primary storage for biometric credentials.
        if isBiometricProtectedItem(biometricTokensKey) {
            let data = try await readProtected(biometricTokensKey)
            return try JSONDecoder().decode(AuthTokens.self, from: data)
        }

        // Legacy migration path: older builds saved biometric tokens under the standard key.
        guard isBiometricProtectedItem(tokensKey) else {
            throw AuthError.biometricFailed("Biometric unlock is not enabled")
        }

        let data = try await readProtected(tokensKey)
        let tokens = try JSONDecoder().decode(AuthTokens.self, from: data)

        try? saveProtected(biometricTokensKey, data: data)
        try? saveTokens(tokens)

        return tokens
    }

    /// Return true if biometric credentials are stored.
    public static func hasProtectedTokens() -> Bool {
        isBiometricProtectedItem(biometricTokensKey) || isBiometricProtectedItem(tokensKey)
    }

    /// Return true when biometric authentication is available.
    public static func isBiometricAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    private static func isBiometricProtectedItem(_ key: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecInteractionNotAllowed {
            return true
        }

        guard status == errSecSuccess,
              let attributes = item as? [String: Any] else {
            return false
        }

        return attributes[kSecAttrAccessControl as String] != nil
    }

    /// Clear biometric-protected tokens only.
    public static func clearProtectedTokens() {
        delete(biometricTokensKey)
        if isBiometricProtectedItem(tokensKey) {
            delete(tokensKey)
        }
    }

    /// Clear all authentication data.
    public static func clearAuth() {
        delete(tokensKey)
        clearProtectedTokens()
        delete("offline_session")
    }
}
