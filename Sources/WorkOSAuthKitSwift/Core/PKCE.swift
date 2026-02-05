import Foundation
import CryptoKit

/// PKCE (Proof Key for Code Exchange) helper for OAuth flows.
public struct PKCE: Sendable {
    public let verifier: String
    public let challenge: String

    /// Generate a new PKCE code verifier and challenge.
    public static func generate() -> PKCE {
        let verifier = randomString(length: 64)
        let challenge = sha256(verifier)
        return PKCE(verifier: verifier, challenge: challenge)
    }

    /// Generate a cryptographically random string.
    private static func randomString(length: Int) -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        var result = ""
        for _ in 0..<length {
            result.append(chars.randomElement()!)
        }
        return result
    }

    /// Compute SHA256 hash and base64url encode it.
    private static func sha256(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        return Data(hash)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
