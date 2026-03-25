import Foundation
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

/// Client for WorkOS Pipes (data integrations) operations.
///
/// **Backend proxy** (recommended for production): set `WorkOSConfiguration.backendUrl`. The app calls your service, which
/// forwards to WorkOS with the secret key:
///
///     POST   /pipes/:slug/authorize          → WorkOS `POST /data-integrations/:slug/authorize`
///     POST   /pipes/:slug/token              → WorkOS `POST /data-integrations/:slug/token`
///     GET    /pipes/:slug/connected-account  → WorkOS `GET  /user_management/users/:id/connected_accounts/:slug`
///     DELETE /pipes/:slug/connected-account  → WorkOS `DELETE …/connected_accounts/:slug`
///
/// **Direct WorkOS** (local dev only): set `WorkOSConfiguration.workosApiKey`. The app calls `https://api.workos.com` with
/// `Authorization: Bearer sk_…`. Do not ship a secret key in a public app binary.
///
public actor PipesClient {
    private let configuration: WorkOSConfiguration
    private weak var authStore: AuthStore?
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public init(configuration: WorkOSConfiguration) {
        self.configuration = configuration
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
        self.decoder.dateDecodingStrategy = .iso8601
        self.encoder.dateEncodingStrategy = .iso8601
    }

    public func attach(authStore: AuthStore) {
        self.authStore = authStore
    }

    // MARK: - Authorization URL

    /// Request an OAuth authorization URL for connecting a provider.
    ///
    /// - Parameters:
    ///   - provider: The provider to connect (e.g. `.github`).
    ///   - returnTo: URL to redirect to after the OAuth flow completes (must be an allowlisted AuthKit redirect URI, e.g. `your-scheme://auth/callback`).
    /// - Returns: The authorization URL string.
    public func getAuthorizationURL(
        provider: PipesProvider,
        returnTo: String? = nil
    ) async throws -> String {
        WorkOSLogger.log("[Pipes] getAuthorizationURL: provider=\(provider.slug), returnTo=\(returnTo ?? "nil")")
        switch try pipesTransport() {
        case .direct(let apiKey):
            let userId = try await requireWorkOSUserId()
            var body: [String: String] = ["user_id": userId]
            if let returnTo, !returnTo.isEmpty {
                body["return_to"] = returnTo
            }
            if let orgId = await currentOrganizationId(), !orgId.isEmpty {
                body["organization_id"] = orgId
            }
            guard let url = configuration.workosRESTURL(path: "/data-integrations/\(provider.slug)/authorize") else {
                throw AuthError.configurationError("Invalid WorkOS API base URL for Pipes")
            }
            let response: PipesAuthorizationResponse = try await perform(
                url: url,
                method: "POST",
                body: body,
                authorization: .workOSSecretKey(apiKey)
            )
            return response.url

        case .proxy:
            var body: [String: String] = [:]
            if let returnTo {
                body["return_to"] = returnTo
            }
            guard let url = configuration.rbacServiceURL(path: "/pipes/\(provider.slug)/authorize") else {
                throw AuthError.configurationError(pipesConfigurationErrorMessage)
            }
            let response: PipesAuthorizationResponse = try await perform(
                url: url,
                method: "POST",
                body: body.isEmpty ? nil : body,
                authorization: .userAccessToken
            )
            return response.url
        }
    }

    // MARK: - Access Token

    /// Retrieve a fresh access token for a connected provider.
    public func getAccessToken(
        provider: PipesProvider
    ) async throws -> PipesAccessTokenEnvelope {
        WorkOSLogger.log("[Pipes] getAccessToken: provider=\(provider.slug)")
        switch try pipesTransport() {
        case .direct(let apiKey):
            let userId = try await requireWorkOSUserId()
            let body = PipesTokenRequestBody(
                userId: userId,
                organizationId: await currentOrganizationId()
            )
            guard let url = configuration.workosRESTURL(path: "/data-integrations/\(provider.slug)/token") else {
                throw AuthError.configurationError("Invalid WorkOS API base URL for Pipes")
            }
            return try await perform(
                url: url,
                method: "POST",
                body: body,
                authorization: .workOSSecretKey(apiKey)
            )

        case .proxy:
            guard let url = configuration.rbacServiceURL(path: "/pipes/\(provider.slug)/token") else {
                throw AuthError.configurationError(pipesConfigurationErrorMessage)
            }
            return try await perform(
                url: url,
                method: "POST",
                authorization: .userAccessToken
            )
        }
    }

    // MARK: - Connected Account

    /// Retrieve the connected account status for a provider.
    public func getConnectedAccount(
        provider: PipesProvider
    ) async throws -> PipesConnectedAccount? {
        WorkOSLogger.log("[Pipes] getConnectedAccount: provider=\(provider.slug)")
        do {
            switch try pipesTransport() {
            case .direct(let apiKey):
                let userId = try await requireWorkOSUserId()
                let path = "/user_management/users/\(userId)/connected_accounts/\(provider.slug)"
                guard let url = configuration.workosRESTURL(path: path) else {
                    throw AuthError.configurationError("Invalid WorkOS API base URL for Pipes")
                }
                let account: PipesConnectedAccount = try await perform(
                    url: url,
                    method: "GET",
                    authorization: .workOSSecretKey(apiKey)
                )
                return account

            case .proxy:
                guard let url = configuration.rbacServiceURL(path: "/pipes/\(provider.slug)/connected-account") else {
                    throw AuthError.configurationError(pipesConfigurationErrorMessage)
                }
                let account: PipesConnectedAccount = try await perform(
                    url: url,
                    method: "GET",
                    authorization: .userAccessToken
                )
                return account
            }
        } catch AuthError.networkError(let message) where message.contains("404") || message.contains("not_found") {
            return nil
        }
    }

    /// Get a lightweight connection status snapshot suitable for UI display.
    public func getConnectionStatus(
        provider: PipesProvider
    ) async throws -> PipesConnectionStatus {
        guard let account = try await getConnectedAccount(provider: provider) else {
            return .disconnected(provider)
        }
        return PipesConnectionStatus(provider: provider, account: account)
    }

    // MARK: - Disconnect

    /// Disconnect (revoke) a connected provider account.
    public func disconnect(provider: PipesProvider) async throws {
        WorkOSLogger.log("[Pipes] disconnect: provider=\(provider.slug)")
        switch try pipesTransport() {
        case .direct(let apiKey):
            let userId = try await requireWorkOSUserId()
            let path = "/user_management/users/\(userId)/connected_accounts/\(provider.slug)"
            guard let url = configuration.workosRESTURL(path: path) else {
                throw AuthError.configurationError("Invalid WorkOS API base URL for Pipes")
            }
            let _: EmptyPipesResponse = try await perform(
                url: url,
                method: "DELETE",
                authorization: .workOSSecretKey(apiKey)
            )

        case .proxy:
            guard let url = configuration.rbacServiceURL(path: "/pipes/\(provider.slug)/connected-account") else {
                throw AuthError.configurationError(pipesConfigurationErrorMessage)
            }
            let _: EmptyPipesResponse = try await perform(
                url: url,
                method: "DELETE",
                authorization: .userAccessToken
            )
        }
    }

    // MARK: - OAuth Flow (Native)

    /// Run the full Pipes OAuth connection flow.
    ///
    /// WorkOS Pipes does **not** accept custom URL schemes as `return_to` — only HTTPS URLs are valid.
    /// Since native apps use custom schemes for redirect URIs, we omit `return_to` entirely and instead:
    ///   1. Open the authorization URL in the system browser.
    ///   2. Poll `getConnectionStatus` until the provider reports connected (or timeout).
    ///
    /// The user completes consent in their browser; WorkOS handles the OAuth exchange server-side.
    /// The browser tab remains open (showing "Connected" or similar) — the app detects completion via polling.
    @MainActor
    public func connectProvider(
        provider: PipesProvider,
        pollingInterval: TimeInterval = 2.5,
        timeout: TimeInterval = 180
    ) async throws -> PipesConnectionStatus {
        WorkOSLogger.log("[Pipes] connectProvider: starting OAuth flow for \(provider.displayName)")

        // 1. Get the authorization URL (no return_to — WorkOS rejects custom schemes).
        let authURLString = try await getAuthorizationURL(
            provider: provider,
            returnTo: nil
        )

        guard let authURL = URL(string: authURLString) else {
            throw AuthError.configurationError("Invalid Pipes authorization URL: \(authURLString)")
        }

        WorkOSLogger.log("[Pipes] connectProvider: opening system browser → \(authURLString)")

        // 2. Open in system browser.
        #if os(iOS)
        await UIApplication.shared.open(authURL)
        #else
        NSWorkspace.shared.open(authURL)
        #endif

        // 3. Poll for connection status until connected or timeout.
        WorkOSLogger.log("[Pipes] connectProvider: polling for connection status (interval=\(pollingInterval)s, timeout=\(timeout)s)")
        let deadline = Date().addingTimeInterval(timeout)

        while Date() < deadline {
            try await Task.sleep(nanoseconds: UInt64(pollingInterval * 1_000_000_000))
            try Task.checkCancellation()

            let status = try await getConnectionStatus(provider: provider)
            if status.isConnected {
                WorkOSLogger.log("[Pipes] connectProvider: \(provider.displayName) connected ✓")
                return status
            }
            if status.needsReauthorization {
                WorkOSLogger.log("[Pipes] connectProvider: \(provider.displayName) needs reauthorization")
                throw PipesError.needsReauthorization(provider)
            }
        }

        WorkOSLogger.log("[Pipes] connectProvider: timed out waiting for \(provider.displayName) connection")
        throw PipesError.connectionFailed(provider)
    }

    // MARK: - Transport

    private enum PipesTransport: Sendable {
        case direct(apiKey: String)
        case proxy
    }

    private var pipesConfigurationErrorMessage: String {
        "Pipes is not configured: set WorkOSRBACServiceURL (backend proxy) or WorkOSAPIKey (direct API, dev only)."
    }

    private func pipesTransport() throws -> PipesTransport {
        if let key = configuration.workosApiKey?.trimmingCharacters(in: .whitespacesAndNewlines), !key.isEmpty {
            return .direct(apiKey: key)
        }
        if let backend = configuration.backendUrl?.trimmingCharacters(in: .whitespacesAndNewlines), !backend.isEmpty {
            return .proxy
        }
        throw AuthError.configurationError(pipesConfigurationErrorMessage)
    }

    private func requireWorkOSUserId() async throws -> String {
        guard let authStore else { throw AuthError.notAuthenticated }
        let sub: String? = await MainActor.run { authStore.userInfo?.sub }
        guard let sub, !sub.isEmpty else { throw AuthError.notAuthenticated }
        return sub
    }

    private func currentOrganizationId() async -> String? {
        guard let authStore else { return nil }
        return await MainActor.run { authStore.userInfo?.org_id }
    }

    private enum PipesAuthorization {
        case userAccessToken
        case workOSSecretKey(String)
    }

    private func perform<Response: Decodable>(
        url: URL,
        method: String = "GET",
        body: (any Encodable)? = nil,
        authorization: PipesAuthorization
    ) async throws -> Response {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let authLabel: String
        switch authorization {
        case .userAccessToken:
            guard let authStore else { throw AuthError.notAuthenticated }
            let token = try await authStore.validAccessToken()
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            authLabel = "userAccessToken"
        case .workOSSecretKey(let key):
            request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
            authLabel = "workOSSecretKey(sk_…\(String(key.suffix(4))))"
        }

        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let bodyData = try encoder.encode(PipesAnyEncodable(body))
            request.httpBody = bodyData
            let bodyPreview = String(data: bodyData, encoding: .utf8) ?? "<binary>"
            WorkOSLogger.log("[Pipes] → \(method) \(url.absoluteString)  auth=\(authLabel)  body=\(bodyPreview)")
        } else {
            WorkOSLogger.log("[Pipes] → \(method) \(url.absoluteString)  auth=\(authLabel)")
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            WorkOSLogger.log("[Pipes] ← non-HTTP response")
            throw AuthError.invalidResponse
        }

        let responsePreview = String(data: data.prefix(512), encoding: .utf8) ?? "<\(data.count) bytes>"
        WorkOSLogger.log("[Pipes] ← \(httpResponse.statusCode)  \(responsePreview)")

        guard (200...299).contains(httpResponse.statusCode) else {
            let message = String(data: data, encoding: .utf8)
                ?? HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode)
            throw AuthError.networkError("\(httpResponse.statusCode): \(message)")
        }

        if Response.self == EmptyPipesResponse.self {
            return EmptyPipesResponse() as! Response
        }

        guard !data.isEmpty else {
            throw AuthError.invalidResponse
        }

        return try decoder.decode(Response.self, from: data)
    }
}

// MARK: - Request Bodies

private struct PipesTokenRequestBody: Encodable {
    let userId: String
    let organizationId: String?

    enum CodingKeys: String, CodingKey {
        case userId = "user_id"
        case organizationId = "organization_id"
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(userId, forKey: .userId)
        try c.encodeIfPresent(organizationId, forKey: .organizationId)
    }
}

// MARK: - Errors

/// Pipes-specific errors.
public enum PipesError: Error, Sendable, LocalizedError {
    case connectionFailed(PipesProvider)
    case needsReauthorization(PipesProvider)
    case notConnected(PipesProvider)
    case tokenUnavailable(PipesProvider, reason: String?)

    public var errorDescription: String? {
        switch self {
        case .connectionFailed(let provider):
            return "\(provider.displayName) connection could not be completed."
        case .needsReauthorization(let provider):
            return "\(provider.displayName) needs to be reauthorized."
        case .notConnected(let provider):
            return "\(provider.displayName) is not connected."
        case .tokenUnavailable(let provider, let reason):
            let base = "\(provider.displayName) access token is unavailable"
            if let reason { return "\(base): \(reason)." }
            return "\(base)."
        }
    }
}

// MARK: - Helpers

private struct EmptyPipesResponse: Decodable {}

private struct PipesAnyEncodable: Encodable {
    private let encodeImpl: (Encoder) throws -> Void

    init(_ wrapped: any Encodable) {
        self.encodeImpl = wrapped.encode(to:)
    }

    func encode(to encoder: Encoder) throws {
        try encodeImpl(encoder)
    }
}

