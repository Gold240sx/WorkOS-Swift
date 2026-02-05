import Foundation
import Combine
import SwiftUI

/// Main authentication store for managing auth state.
@MainActor
public final class AuthStore: ObservableObject {

    // MARK: - Published State

    @Published public private(set) var state: AuthState = .loading
    @Published public private(set) var userInfo: UserInfo?
    @Published public private(set) var tokens: AuthTokens?
    @Published public private(set) var activeOrgSession: OrgSession?
    @Published public var organizations: [Organization] = []
    @Published public private(set) var isOnline: Bool = true

    // MARK: - Dependencies

    private let configuration: WorkOSConfiguration
    private let authController: WorkOSAuthController
    private var refreshTask: Task<Void, Never>?
    private var enforcementTask: Task<Void, Never>?
    private let networkMonitor: NetworkMonitor
    private var cancellables: Set<AnyCancellable> = []

    // MARK: - Initialization

    public init(configuration: WorkOSConfiguration) {
        self.configuration = configuration
        self.authController = WorkOSAuthController(configuration: configuration)
        self.networkMonitor = NetworkMonitor()

        // Enforce auth invariants once we regain connectivity.
        networkMonitor.$isOnline
            .removeDuplicates()
            .receive(on: DispatchQueue.main)
            .sink { [weak self] online in
                guard let self else { return }
                self.isOnline = online
                if online {
                    self.enforceOnlineAuthInvariant()
                    self.startEnforcementLoopIfNeeded()
                } else {
                    self.enforcementTask?.cancel()
                    self.enforcementTask = nil
                }
            }
            .store(in: &cancellables)
    }

    // MARK: - Bootstrap

    /// Initialize auth state from persisted data.
    public func bootstrap() async {
        state = .loading
        print("[AuthStore] Starting bootstrap...")

        // Try to restore offline session first
        if let offlineSession = restoreOfflineSession() {
            print("[AuthStore] Found offline session")
            self.tokens = offlineSession.tokens
            self.userInfo = UserInfo(
                sub: offlineSession.userId,
                email: offlineSession.email
            )
            self.activeOrgSession = OrgSession(
                orgId: offlineSession.orgId,
                role: offlineSession.role,
                permissions: Set(offlineSession.permissions.compactMap { Permission(rawValue: $0) })
            )
            self.state = .authenticated
            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }

            // Try to refresh tokens in background
            refreshTask = Task {
                await refreshTokensIfNeeded()
            }

            log("Restored from offline session")
            return
        }

        // Try to load tokens from keychain
        if let savedTokens = SecureKeychain.loadTokens() {
            print("[AuthStore] Found saved tokens in keychain")
            self.tokens = savedTokens

            if !savedTokens.isExpired {
                print("[AuthStore] Tokens not expired, loading user info")
                await loadUserInfo()
                state = .authenticated
                if isOnline {
                    enforceOnlineAuthInvariant()
                    startEnforcementLoopIfNeeded()
                }
                log("Loaded saved tokens")
                return
            } else {
                print("[AuthStore] Tokens expired, attempting refresh")
                // Try to refresh
                do {
                    try await refreshTokens()
                    await loadUserInfo()
                    state = .authenticated
                    if isOnline {
                        enforceOnlineAuthInvariant()
                        startEnforcementLoopIfNeeded()
                    }
                    log("Refreshed expired tokens")
                    return
                } catch {
                    print("[AuthStore] Token refresh failed: \(error)")
                    log("Token refresh failed: \(error)")
                }
            }
        } else {
            print("[AuthStore] No saved tokens found")
        }

        print("[AuthStore] Setting state to unauthenticated")
        state = .unauthenticated
    }

    // MARK: - Sign In

    /// Start the sign-in flow.
    public func signIn() async throws {
        state = .loading

        do {
            let result = try await authController.signIn()
            self.tokens = result.tokens
            self.userInfo = result.userInfo

            // Save to keychain
            try SecureKeychain.saveTokens(result.tokens)

            // Load organizations
            await loadOrganizations()

            state = .authenticated
            log("Sign in successful for user: \(result.userInfo.email)")
            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }

        } catch AuthError.userCancelled {
            state = .unauthenticated
            throw AuthError.userCancelled
        } catch {
            state = .unauthenticated
            throw error
        }
    }

    // MARK: - Sign Out

    /// Sign out and clear all auth data.
    public func signOut() {
        tokens = nil
        userInfo = nil
        activeOrgSession = nil
        organizations = []

        SecureKeychain.clearAuth()
        clearOfflineSession()

        refreshTask?.cancel()
        refreshTask = nil
        enforcementTask?.cancel()
        enforcementTask = nil

        state = .unauthenticated
        log("Signed out")
    }

    /// When online, force the app back to the sign-in page if:
    /// - we don't have a user id (`userInfo` is missing), or
    /// - the session is expired.
    ///
    /// This is intentionally strict so we don't silently keep a stale session once connectivity returns.
    private func enforceOnlineAuthInvariant() {
        guard isOnline else { return }

        // If we're missing core identity, force sign-in.
        if userInfo?.sub.isEmpty != false {
            if state == .authenticated {
                log("Online but userId missing; forcing sign-out")
            }
            signOut()
            return
        }

        // If token/session expired, force sign-in.
        if let t = tokens, t.isExpired {
            log("Online but session expired; forcing sign-out")
            signOut()
            return
        }

        // If we say we're authenticated but are missing tokens, force sign-in.
        if state == .authenticated && tokens == nil {
            log("Online but tokens missing; forcing sign-out")
            signOut()
            return
        }
    }

    private func startEnforcementLoopIfNeeded() {
        guard enforcementTask == nil else { return }
        enforcementTask = Task { [weak self] in
            while !Task.isCancelled {
                await MainActor.run {
                    self?.enforceOnlineAuthInvariant()
                }
                try? await Task.sleep(nanoseconds: 15 * 1_000_000_000) // 15s
            }
        }
    }

    // MARK: - Token Management

    /// Get a valid access token, refreshing if needed.
    public func validAccessToken() async throws -> String {
        guard var currentTokens = tokens else {
            throw AuthError.notAuthenticated
        }

        if currentTokens.expiresSoon(within: 60) {
            currentTokens = try await refreshTokens()
        }

        return currentTokens.accessToken
    }

    /// Refresh tokens.
    @discardableResult
    public func refreshTokens() async throws -> AuthTokens {
        guard let currentTokens = tokens else {
            throw AuthError.notAuthenticated
        }

        let newTokens = try await authController.refreshTokens(
            refreshToken: currentTokens.refreshToken
        )

        self.tokens = newTokens
        try SecureKeychain.saveTokens(newTokens)

        log("Tokens refreshed")
        return newTokens
    }

    private func refreshTokensIfNeeded() async {
        guard let tokens = tokens, tokens.expiresSoon(within: 300) else {
            return
        }

        do {
            try await refreshTokens()
        } catch {
            log("Background token refresh failed: \(error)")
        }
    }

    // MARK: - User Info

    private func loadUserInfo() async {
        guard let tokens = tokens else { return }

        if let decoded = decodeUserInfo(from: tokens.idToken) {
            self.userInfo = decoded
        }
    }

    private func decodeUserInfo(from idToken: String) -> UserInfo? {
        let segments = idToken.split(separator: ".")
        guard segments.count == 3 else { return nil }

        var base64 = String(segments[1])
        // Pad base64 if needed
        let padding = (4 - base64.count % 4) % 4
        base64.append(contentsOf: repeatElement("=", count: padding))

        guard let data = Data(base64Encoded: base64),
              let userInfo = try? JSONDecoder().decode(UserInfo.self, from: data) else {
            return nil
        }

        return userInfo
    }

    // MARK: - Organizations

    /// Load organizations from backend.
    public func loadOrganizations() async {
        // In production, call your backend to get user's organizations
        // For now, this is a placeholder
    }

    /// Switch to a different organization.
    public func switchOrganization(to org: Organization) async throws {
        // Call backend to get org-scoped session
        guard let backendUrl = configuration.backendUrl,
              let url = URL(string: "\(backendUrl)/auth/exchange-org") else {
            throw AuthError.configurationError("Backend URL not configured")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "workosUserId": userInfo?.sub ?? "",
            "workosOrgId": org.workosOrgId
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw AuthError.networkError("Failed to switch organization")
        }

        let result = try JSONDecoder().decode(OrgSwitchResponse.self, from: data)

        activeOrgSession = OrgSession(
            orgId: result.org.id,
            role: result.role,
            permissions: Set(result.permissions.compactMap { Permission(rawValue: $0) })
        )

        // Persist for offline
        persistOfflineSession()

        log("Switched to org: \(org.name)")
    }

    // MARK: - Biometric Unlock

    /// Enable biometric unlock.
    public func enableBiometricUnlock() async throws {
        guard let tokens = tokens else {
            throw AuthError.notAuthenticated
        }

        try SecureKeychain.saveTokensProtected(tokens)
        log("Biometric unlock enabled")
    }

    /// Unlock with biometrics.
    public func unlockWithBiometrics() async throws {
        let tokens = try await SecureKeychain.loadTokensProtected()
        self.tokens = tokens

        if let userInfo = decodeUserInfo(from: tokens.idToken) {
            self.userInfo = userInfo
        }

        state = .authenticated
        log("Unlocked with biometrics")
    }

    // MARK: - Offline Session

    private func persistOfflineSession() {
        guard let tokens = tokens,
              let userInfo = userInfo else { return }

        let session = OfflineSession(
            tokens: tokens,
            userId: userInfo.sub,
            email: userInfo.email,
            orgId: activeOrgSession?.orgId ?? "",
            role: activeOrgSession?.role ?? "",
            permissions: activeOrgSession?.permissions.map { $0.rawValue } ?? [],
            lastAuthenticatedAt: Date()
        )

        if let data = try? JSONEncoder().encode(session) {
            UserDefaults.standard.set(data, forKey: "offline_session")
        }
    }

    private func restoreOfflineSession() -> OfflineSession? {
        guard let data = UserDefaults.standard.data(forKey: "offline_session"),
              let session = try? JSONDecoder().decode(OfflineSession.self, from: data) else {
            return nil
        }

        // Check if offline session is still valid
        let elapsed = abs(session.lastAuthenticatedAt.timeIntervalSinceNow)
        guard elapsed < configuration.maxOfflineDuration else {
            clearOfflineSession()
            return nil
        }

        return session
    }

    private func clearOfflineSession() {
        UserDefaults.standard.removeObject(forKey: "offline_session")
    }

    // MARK: - Refresh Org Session

    /// Refresh organization session (call after role changes).
    public func refreshOrgSession() async {
        guard let org = organizations.first(where: { $0.id == activeOrgSession?.orgId }) else {
            return
        }

        try? await switchOrganization(to: org)
    }

    // MARK: - Logging

    private func log(_ message: String) {
        if configuration.debugLogging {
            print("[AuthStore] \(message)")
        }
    }
}

// MARK: - Response Types

private struct OrgSwitchResponse: Decodable {
    let success: Bool
    let org: OrgInfo
    let role: String
    let permissions: [String]

    struct OrgInfo: Decodable {
        let id: String
        let workosOrgId: String
        let name: String
    }
}

/// Offline session for persistence.
struct OfflineSession: Codable {
    let tokens: AuthTokens
    let userId: String
    let email: String
    let orgId: String
    let role: String
    let permissions: [String]
    let lastAuthenticatedAt: Date
}
