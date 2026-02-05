import Foundation

/// Friendly duration helper for offline sessions.
public enum OfflineSessionDuration: Sendable, Equatable {
    case minutes(Int)
    case hours(Int)
    case days(Int)
    case never

    public var timeInterval: TimeInterval {
        switch self {
        case .minutes(let value):
            return max(0, TimeInterval(value)) * 60
        case .hours(let value):
            return max(0, TimeInterval(value)) * 60 * 60
        case .days(let value):
            return max(0, TimeInterval(value)) * 24 * 60 * 60
        case .never:
            return .infinity
        }
    }
}

/// Configuration for WorkOS AuthKit.
public struct WorkOSConfiguration: Sendable {
    /// Your WorkOS Client ID.
    public let clientId: String

    /// Your app's redirect URI (custom URL scheme).
    public let redirectUri: String

    /// Custom URL scheme (extracted from redirectUri).
    public let callbackScheme: String

    /// WorkOS API base URL.
    public let apiBaseUrl: String

    /// Your backend API base URL (for token verification).
    public var backendUrl: String?

    /// Whether to enable debug logging.
    public var debugLogging: Bool

    /// Maximum offline session duration (seconds).
    public var maxOfflineDuration: TimeInterval

    public init(
        clientId: String,
        redirectUri: String,
        backendUrl: String? = nil,
        apiBaseUrl: String = "https://api.workos.com",
        debugLogging: Bool = false,
        maxOfflineDuration: OfflineSessionDuration = .days(7)
    ) {
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackScheme = URL(string: redirectUri)?.scheme ?? "yourapp"
        self.apiBaseUrl = apiBaseUrl
        self.backendUrl = backendUrl
        self.debugLogging = debugLogging
        self.maxOfflineDuration = maxOfflineDuration.timeInterval
    }

    @available(*, deprecated, message: "Use OfflineSessionDuration (e.g. .days(7), .hours(12), .never).")
    public init(
        clientId: String,
        redirectUri: String,
        backendUrl: String? = nil,
        apiBaseUrl: String = "https://api.workos.com",
        debugLogging: Bool = false,
        maxOfflineDuration: TimeInterval
    ) {
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackScheme = URL(string: redirectUri)?.scheme ?? "yourapp"
        self.apiBaseUrl = apiBaseUrl
        self.backendUrl = backendUrl
        self.debugLogging = debugLogging
        self.maxOfflineDuration = maxOfflineDuration
    }

    /// Build the authorization URL for OAuth flow.
    public func authorizationUrl(pkce: PKCE, state: String? = nil) -> URL? {
        var components = URLComponents(string: "\(apiBaseUrl)/user_management/authorize")

        var queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "provider", value: "authkit")
        ]

        if let state = state {
            queryItems.append(URLQueryItem(name: "state", value: state))
        }

        components?.queryItems = queryItems
        return components?.url
    }

    /// Build the token endpoint URL.
    public var tokenUrl: URL? {
        URL(string: "\(apiBaseUrl)/user_management/authenticate")
    }

    /// Build the user info endpoint URL.
    public var userInfoUrl: URL? {
        URL(string: "\(apiBaseUrl)/user_management/userinfo")
    }
}
