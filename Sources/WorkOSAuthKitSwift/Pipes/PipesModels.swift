import Foundation

// MARK: - Provider

/// Known WorkOS Pipes providers.
public enum PipesProvider: String, Sendable, Codable, CaseIterable, Identifiable {
    case github
    case slack
    case google
    case salesforce

    public var id: String { rawValue }

    /// The URL slug used in WorkOS Pipes API paths (`/data-integrations/:slug/…`).
    public var slug: String { rawValue }

    /// Human-readable display name.
    public var displayName: String {
        switch self {
        case .github:     return "GitHub"
        case .slack:      return "Slack"
        case .google:     return "Google"
        case .salesforce: return "Salesforce"
        }
    }
}

// MARK: - Authorization

/// Response from `POST /pipes/:slug/authorize` (backend proxy) or `POST /data-integrations/:slug/authorize` (WorkOS API).
public struct PipesAuthorizationResponse: Decodable, Sendable {
    /// The OAuth authorization URL the user should be redirected to.
    public let url: String

    enum CodingKeys: String, CodingKey {
        case url
        case authorizationURL = "authorization_url"
        case link
    }

    public init(url: String) {
        self.url = url
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let u = try c.decodeIfPresent(String.self, forKey: .url), !u.isEmpty {
            url = u
        } else if let u = try c.decodeIfPresent(String.self, forKey: .authorizationURL), !u.isEmpty {
            url = u
        } else if let u = try c.decodeIfPresent(String.self, forKey: .link), !u.isEmpty {
            url = u
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Missing authorization URL (expected url, authorization_url, or link)."))
        }
    }
}

// MARK: - Connected Account

/// The state of a Pipes connected account.
public enum PipesConnectionState: String, Codable, Sendable {
    case connected
    case disconnected
    case needsReauthorization = "needs_reauthorization"
}

/// A user's connected account for a specific provider.
public struct PipesConnectedAccount: Decodable, Sendable {
    public let object: String?
    public let id: String?
    public let userId: String?
    public let organizationId: String?
    public let scopes: [String]
    public let state: PipesConnectionState
    public let createdAt: String?
    public let updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case object
        case id
        case userId = "user_id"
        case organizationId = "organization_id"
        case scopes
        case state
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    public var isConnected: Bool {
        state == .connected
    }
}

// MARK: - Access Token

/// An access token retrieved from WorkOS Pipes for a connected provider.
public struct PipesAccessTokenEnvelope: Decodable, Sendable {
    /// Whether the connected account is active.
    public let active: Bool

    /// The access token details (present when `active` is true).
    public let accessToken: PipesAccessTokenDetail?

    /// An error code when the token cannot be issued.
    /// Common values: `"needs_reauthorization"`, `"not_installed"`.
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case active
        case accessToken = "access_token"
        case error
    }
}

/// Detail of a Pipes access token.
public struct PipesAccessTokenDetail: Decodable, Sendable {
    public let object: String?
    public let accessToken: String
    public let expiresAt: String?
    public let scopes: [String]
    public let missingScopes: [String]

    enum CodingKeys: String, CodingKey {
        case object
        case accessToken = "access_token"
        case expiresAt = "expires_at"
        case scopes
        case missingScopes = "missing_scopes"
    }

    /// The raw token string for use in GitHub API calls.
    public var token: String { accessToken }

    /// Parse `expiresAt` into a `Date`.
    public var expirationDate: Date? {
        guard let expiresAt else { return nil }
        return ISO8601DateFormatter().date(from: expiresAt)
    }

    /// Whether the token is expired or expiring within a given window.
    public func isExpired(within interval: TimeInterval = 0) -> Bool {
        guard let date = expirationDate else { return false }
        return date <= Date().addingTimeInterval(interval)
    }
}

// MARK: - Connection Status (convenience)

/// Lightweight snapshot of a provider connection, used by UI components.
public struct PipesConnectionStatus: Sendable {
    public let provider: PipesProvider
    public let isConnected: Bool
    public let scopes: [String]
    public let needsReauthorization: Bool
    public let error: String?

    public init(
        provider: PipesProvider,
        isConnected: Bool = false,
        scopes: [String] = [],
        needsReauthorization: Bool = false,
        error: String? = nil
    ) {
        self.provider = provider
        self.isConnected = isConnected
        self.scopes = scopes
        self.needsReauthorization = needsReauthorization
        self.error = error
    }

    /// Create from a connected account response.
    public init(provider: PipesProvider, account: PipesConnectedAccount) {
        self.provider = provider
        self.isConnected = account.isConnected
        self.scopes = account.scopes
        self.needsReauthorization = account.state == .needsReauthorization
        self.error = nil
    }

    /// Disconnected / not-installed state.
    public static func disconnected(_ provider: PipesProvider) -> PipesConnectionStatus {
        PipesConnectionStatus(provider: provider)
    }
}
