import Foundation

/// Authentication tokens from WorkOS.
public struct AuthTokens: Codable, Sendable {
    public let accessToken: String
    public let idToken: String
    public let refreshToken: String
    public let expiresAt: Date

    public init(
        accessToken: String,
        idToken: String,
        refreshToken: String,
        expiresAt: Date
    ) {
        self.accessToken = accessToken
        self.idToken = idToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
    }

    /// Check if the access token is expired.
    public var isExpired: Bool {
        expiresAt <= Date()
    }

    /// Check if the token will expire soon (within given interval).
    public func expiresSoon(within interval: TimeInterval = 60) -> Bool {
        expiresAt <= Date().addingTimeInterval(interval)
    }
}

/// Authentication result containing tokens and user info.
public struct AuthResult: Sendable {
    public let tokens: AuthTokens
    public let userInfo: UserInfo

    public init(tokens: AuthTokens, userInfo: UserInfo) {
        self.tokens = tokens
        self.userInfo = userInfo
    }
}

/// Response from WorkOS authenticate endpoint.
public struct TokenResponse: Decodable {
    public let access_token: String
    public let refresh_token: String
    public let user: WorkOSUser
    public let organization_id: String?
    public let authentication_method: String?

    /// Convert to AuthTokens model.
    public func toAuthTokens() -> AuthTokens {
        // WorkOS access tokens are JWTs valid for 5 minutes by default
        // Use the access token as both access and ID token since WorkOS doesn't provide separate ID token
        AuthTokens(
            accessToken: access_token,
            idToken: access_token, // Use access token as ID token (it's a JWT with user claims)
            refreshToken: refresh_token,
            expiresAt: Date().addingTimeInterval(5 * 60) // 5 minutes default
        )
    }

    /// Get user info from the response
    public func toUserInfo() -> UserInfo {
        UserInfo(
            sub: user.id,
            email: user.email,
            email_verified: user.email_verified,
            given_name: user.first_name,
            family_name: user.last_name,
            picture: user.profile_picture_url,
            org_id: organization_id
        )
    }
}

/// WorkOS User object from authenticate response.
public struct WorkOSUser: Decodable {
    public let id: String
    public let email: String
    public let email_verified: Bool?
    public let first_name: String?
    public let last_name: String?
    public let profile_picture_url: String?
    public let created_at: String?
    public let updated_at: String?
}

/// User information decoded from ID token.
public struct UserInfo: Codable, Sendable {
    public let sub: String // WorkOS user ID
    public let email: String
    public let email_verified: Bool?
    public let given_name: String?
    public let family_name: String?
    public let picture: String?
    public let org_id: String?

    public init(
        sub: String,
        email: String,
        email_verified: Bool? = nil,
        given_name: String? = nil,
        family_name: String? = nil,
        picture: String? = nil,
        org_id: String? = nil
    ) {
        self.sub = sub
        self.email = email
        self.email_verified = email_verified
        self.given_name = given_name
        self.family_name = family_name
        self.picture = picture
        self.org_id = org_id
    }

    /// Full name from given and family name.
    public var fullName: String? {
        [given_name, family_name]
            .compactMap { $0 }
            .joined(separator: " ")
            .nilIfEmpty
    }
}

/// Authentication state.
public enum AuthState: Sendable {
    case loading
    case authenticated
    case unauthenticated
}

/// Authentication errors.
public enum AuthError: Error, Sendable {
    case notAuthenticated
    case tokenExpired
    case tokenRefreshFailed
    case invalidResponse
    case networkError(String)
    case biometricFailed(String)
    case keychainError(String)
    case userCancelled
    case configurationError(String)
}

// MARK: - String Extension

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
