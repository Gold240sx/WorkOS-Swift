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
    @Published public private(set) var authorizationSnapshot: AuthorizationSnapshot?
    @Published public var organizations: [Organization] = []
    @Published public private(set) var isOnline: Bool = true

    public var effectiveRole: String? {
        effectiveRoles.first
    }

    public var effectiveRoles: [String] {
        if let activeOrgSession {
            var values: [String] = []

            if !activeOrgSession.role.isEmpty {
                values.append(activeOrgSession.role)
            }

            values.append(contentsOf: activeOrgSession.organizationRoles)
            return deduplicatedRoleSlugs(values)
        }

        return deduplicatedRoleSlugs(inferredRoleSlugs())
    }

    // MARK: - Dependencies

    private let configuration: WorkOSConfiguration
    private let authController: WorkOSAuthController
    private var refreshTask: Task<Void, Never>?
    private var enforcementTask: Task<Void, Never>?
    private let networkMonitor: NetworkMonitor
    private var cancellables: Set<AnyCancellable> = []
    private var refreshInFlight = false

    public let rbacClient: RBACClient
    public let vaultClient: VaultClient

    // MARK: - Initialization

    public init(configuration: WorkOSConfiguration) {
        self.configuration = configuration
        WorkOSLogger.configure(enabled: configuration.debugLogging)
        self.authController = WorkOSAuthController(configuration: configuration)
        self.networkMonitor = NetworkMonitor()
        self.rbacClient = RBACClient(configuration: configuration)
        self.vaultClient = VaultClient(configuration: configuration)

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

        Task { [weak self] in
            guard let self else { return }
            await self.rbacClient.attach(authStore: self)
            await self.vaultClient.attach(authStore: self)
        }
    }

    // MARK: - Bootstrap

    /// Initialize auth state from persisted data.
    public func bootstrap() async {
        state = .loading
        log("Starting bootstrap")

        if let offlineSession = restoreOfflineSession() {
            restore(from: offlineSession)
            state = .authenticated
            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }
            refreshTask = Task { [weak self] in
                guard let self else { return }
                await self.refreshTokensIfNeeded()
                await self.refreshAuthorizationContext()
            }
            log("Restored from offline session")
            return
        }

        guard let savedTokens = SecureKeychain.loadTokens() else {
            state = .unauthenticated
            log("No saved tokens found")
            return
        }

        self.tokens = savedTokens

        do {
            if savedTokens.isExpired {
                _ = try await refreshTokens()
            }

            await loadUserInfo()
            await refreshAuthorizationContext()
            state = .authenticated

            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }

            log("Loaded saved tokens")
        } catch {
            log("Bootstrap failed: \(error)")
            signOut()
        }
    }

    // MARK: - Sign In

    /// Start the sign-in flow.
    public func signIn(forceAccountSelection: Bool = false) async throws {
        state = .loading

        do {
            let result = try await authController.signIn(forceAccountSelection: forceAccountSelection)
            tokens = result.tokens
            userInfo = result.userInfo

            try SecureKeychain.saveTokens(result.tokens)
            await refreshAuthorizationContext()

            state = .authenticated
            persistOfflineSession()

            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }

            log("Sign in successful for user: \(result.userInfo.email)")
        } catch AuthError.userCancelled {
            state = .unauthenticated
            throw AuthError.userCancelled
        } catch {
            state = .unauthenticated
            throw error
        }
    }

    // MARK: - Embedded Sign In

    /// Build an authorization URL for use with an embedded WKWebView flow.
    public func buildEmbeddedAuthURL(forceAccountSelection: Bool = false) -> (url: URL, session: EmbeddedAuthSession)? {
        let pkce = PKCE.generate()
        let state = UUID().uuidString.lowercased()
        guard let url = configuration.authorizationUrl(
            pkce: pkce,
            state: state,
            prompt: forceAccountSelection ? "select_account" : nil,
            maxAge: forceAccountSelection ? 0 : nil
        ) else { return nil }
        let session = EmbeddedAuthSession(pkce: pkce, state: state, callbackScheme: configuration.callbackScheme)
        return (url, session)
    }

    /// Complete an embedded sign-in after the WKWebView intercepts the callback URL.
    public func completeEmbeddedAuth(callbackURL: URL, session: EmbeddedAuthSession) async throws {
        state = .loading
        do {
            guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
                throw AuthError.invalidResponse
            }

            if let errorValue = components.queryItems?.first(where: { $0.name == "error" })?.value {
                let desc = components.queryItems?.first(where: { $0.name == "error_description" })?.value ?? errorValue
                throw AuthError.networkError(desc)
            }

            let returnedState = components.queryItems?.first(where: { $0.name == "state" })?.value
            guard returnedState == session.state else {
                throw AuthError.invalidResponse
            }

            guard let code = components.queryItems?.first(where: { $0.name == "code" })?.value else {
                throw AuthError.invalidResponse
            }

            let result = try await authController.exchangeCode(code, pkce: session.pkce)
            tokens = result.tokens
            userInfo = result.userInfo
            try SecureKeychain.saveTokens(result.tokens)
            await refreshAuthorizationContext()
            self.state = .authenticated
            persistOfflineSession()

            if isOnline {
                enforceOnlineAuthInvariant()
                startEnforcementLoopIfNeeded()
            }
            log("Embedded sign in successful for user: \(result.userInfo.email)")
        } catch {
            self.state = .unauthenticated
            throw error
        }
    }

    // MARK: - Sign Out

    /// Sign out and clear all auth data.
    public func signOut() {
        tokens = nil
        userInfo = nil
        activeOrgSession = nil
        authorizationSnapshot = nil
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

    private func enforceOnlineAuthInvariant() {
        guard isOnline else { return }
        guard state == .authenticated else { return }

        if userInfo?.sub.isEmpty != false {
            signOut()
            return
        }

        if let currentTokens = tokens, currentTokens.isExpired {
            if refreshInFlight { return }
            refreshInFlight = true
            Task { @MainActor [weak self] in
                guard let self else { return }
                do {
                    _ = try await self.refreshTokens()
                    await self.refreshAuthorizationContext()
                    self.refreshInFlight = false
                    self.state = .authenticated
                } catch {
                    self.refreshInFlight = false
                    self.log("Online but session expired; refresh failed")
                    self.signOut()
                }
            }
            return
        }

        if state == .authenticated && tokens == nil {
            signOut()
        }
    }

    private func startEnforcementLoopIfNeeded() {
        guard enforcementTask == nil else { return }
        enforcementTask = Task { [weak self] in
            while !Task.isCancelled {
                await MainActor.run {
                    self?.enforceOnlineAuthInvariant()
                }
                try? await Task.sleep(nanoseconds: 15 * 1_000_000_000)
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

        let newTokens = try await authController.refreshTokens(refreshToken: currentTokens.refreshToken)
        tokens = newTokens
        try SecureKeychain.saveTokens(newTokens)
        await loadUserInfo()
        persistOfflineSession()
        log("Tokens refreshed")
        return newTokens
    }

    private func refreshTokensIfNeeded() async {
        guard let tokens, tokens.expiresSoon(within: 300) else { return }
        do {
            try await refreshTokens()
        } catch {
            log("Background token refresh failed: \(error)")
        }
    }

    // MARK: - User Info

    private func loadUserInfo() async {
        guard let tokens else { return }

        if let decoded = decodeUserInfo(from: tokens.idToken) ?? decodeUserInfo(from: tokens.accessToken) {
            userInfo = decoded
        }
    }

    private func decodeUserInfo(from jwt: String) -> UserInfo? {
        guard let data = decodeJWTPayload(jwt) else { return nil }
        return try? JSONDecoder().decode(UserInfo.self, from: data)
    }

    // MARK: - Organizations

    public func loadOrganizations() async {
        if configuration.backendUrl != nil {
            do {
                organizations = try await rbacClient.listOrganizations()
                persistOfflineSession()
                return
            } catch {
                log("Failed to load organizations from RBAC service: \(error)")
            }
        }

        organizations = inferOrganizationsFromClaims()
        rebuildAuthorizationSnapshot()
    }

    /// Refresh the current authorization context from the RBAC service when available.
    public func refreshAuthorizationContext() async {
        if configuration.backendUrl != nil {
            do {
                let preferredOrgId = activeOrgSession?.workosOrganizationId ?? userInfo?.org_id
                let snapshot = try await rbacClient.fetchAuthorizationSnapshot(organizationId: preferredOrgId)
                apply(snapshot: snapshot)
                persistOfflineSession()
                return
            } catch {
                log("Failed to refresh authorization snapshot: \(error)")
            }
        }

        let fallbackOrgs = inferOrganizationsFromClaims()
        organizations = fallbackOrgs
        activeOrgSession = inferFallbackSession(organizations: fallbackOrgs)
        rebuildAuthorizationSnapshot()
        persistOfflineSession()
    }

    public func selectOrganization(_ org: Organization) async throws {
        if configuration.backendUrl != nil {
            let snapshot = try await rbacClient.fetchAuthorizationSnapshot(organizationId: org.workosOrgId)
            apply(snapshot: snapshot)
        } else {
            activeOrgSession = inferFallbackSession(organizations: [org])?.selecting(resource: nil)
                ?? OrgSession(
                    orgId: org.id,
                    workosOrganizationId: org.workosOrgId,
                    organizationMembershipId: inferredMembershipId(),
                    role: inferredRoleSlugs().first ?? "member",
                    permissions: inferredPermissions(),
                    organizationRoles: inferredRoleSlugs()
                )
            organizations = mergeOrganizations(existing: organizations, with: org)
            rebuildAuthorizationSnapshot()
        }

        persistOfflineSession()
        log("Switched to org: \(org.name)")
    }

    /// Compatibility alias for older integrations.
    public func switchOrganization(to org: Organization) async throws {
        try await selectOrganization(org)
    }

    public func selectResourceContext(_ resource: AuthorizationResource?) async {
        activeOrgSession = activeOrgSession?.selecting(resource: resource)
        rebuildAuthorizationSnapshot()
        persistOfflineSession()
    }

    public func checkPermission(
        _ permission: Permission,
        resource: AuthorizationResource? = nil
    ) async throws -> Bool {
        guard let session = activeOrgSession else { return false }
        guard let resource,
              configuration.backendUrl != nil,
              let membershipId = session.organizationMembershipId else {
            return has(permission, in: resource)
        }

        do {
            return try await rbacClient.checkPermission(
                organizationMembershipId: membershipId,
                permission: permission,
                resource: resource
            )
        } catch {
            log("Falling back to cached permission check: \(error)")
            return has(permission, in: resource)
        }
    }

    public func listAccessibleResources(
        permission: Permission,
        parent: AuthorizationResource? = nil
    ) async throws -> [AuthorizationResource] {
        guard let session = activeOrgSession else { return [] }
        guard configuration.backendUrl != nil,
              let membershipId = session.organizationMembershipId else {
            return session.accessibleResources
        }

        let resources = try await rbacClient.listAccessibleResources(
            organizationMembershipId: membershipId,
            permission: permission,
            parent: parent
        )

        let merged = Array(Set(session.accessibleResources + resources))
        activeOrgSession = OrgSession(
            orgId: session.orgId,
            workosOrganizationId: session.workosOrganizationId,
            organizationMembershipId: session.organizationMembershipId,
            role: session.role,
            permissions: session.permissions,
            organizationRoles: session.organizationRoles,
            selectedResource: session.selectedResource,
            accessibleResources: merged,
            resourcePermissions: session.resourcePermissions,
            roleAssignments: session.roleAssignments,
            lastRefreshedAt: Date()
        )
        rebuildAuthorizationSnapshot()
        persistOfflineSession()
        return resources
    }

    // MARK: - Biometric Unlock

    public var canUseBiometricUnlock: Bool {
        SecureKeychain.isBiometricAvailable() && SecureKeychain.hasProtectedTokens()
    }

    public func enableBiometricUnlock() async throws {
        guard let tokens else {
            throw AuthError.notAuthenticated
        }

        try SecureKeychain.saveTokensProtected(tokens)
        persistOfflineSession()
        log("Biometric unlock enabled")
    }

    public func unlockWithBiometrics() async throws {
        let tokens = try await SecureKeychain.loadTokensProtected()
        self.tokens = tokens
        try? SecureKeychain.saveTokens(tokens)
        await loadUserInfo()
        await refreshAuthorizationContext()
        state = .authenticated
        persistOfflineSession()

        if isOnline {
            enforceOnlineAuthInvariant()
            startEnforcementLoopIfNeeded()
        }

        log("Unlocked with biometrics")
    }

    // MARK: - Offline Session

    private func persistOfflineSession() {
        guard let tokens, let userInfo else { return }

        let session = OfflineSession(
            tokens: tokens,
            userId: userInfo.sub,
            email: userInfo.email,
            orgId: activeOrgSession?.orgId ?? "",
            role: activeOrgSession?.role ?? "",
            permissions: activeOrgSession?.permissions.map(\.rawValue) ?? [],
            organizationMembershipId: activeOrgSession?.organizationMembershipId,
            organizations: organizations,
            authorizationSnapshot: authorizationSnapshot,
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

        let elapsed = abs(session.lastAuthenticatedAt.timeIntervalSinceNow)
        guard elapsed < configuration.maxOfflineDuration else {
            clearOfflineSession()
            return nil
        }

        return session
    }

    private func restore(from offlineSession: OfflineSession) {
        tokens = offlineSession.tokens
        userInfo = UserInfo(
            sub: offlineSession.userId,
            email: offlineSession.email,
            org_id: offlineSession.authorizationSnapshot?.activeOrgSession?.workosOrganizationId ?? offlineSession.orgId.nilIfEmpty
        )

        if let snapshot = offlineSession.authorizationSnapshot {
            apply(snapshot: snapshot)
            return
        }

        organizations = offlineSession.organizations
        if !offlineSession.orgId.isEmpty {
            activeOrgSession = OrgSession(
                orgId: offlineSession.orgId,
                organizationMembershipId: offlineSession.organizationMembershipId,
                role: offlineSession.role,
                permissions: Set(offlineSession.permissions.map(Permission.init(rawValue:))),
                organizationRoles: offlineSession.role.isEmpty ? [] : [offlineSession.role]
            )
        }
        rebuildAuthorizationSnapshot()
    }

    private func clearOfflineSession() {
        UserDefaults.standard.removeObject(forKey: "offline_session")
    }

    // MARK: - Refresh Org Session

    public func refreshOrgSession() async {
        await refreshAuthorizationContext()
    }

    // MARK: - Helpers

    private func apply(snapshot: AuthorizationSnapshot) {
        organizations = snapshot.organizations
        activeOrgSession = snapshot.activeOrgSession
        authorizationSnapshot = snapshot
    }

    private func rebuildAuthorizationSnapshot() {
        authorizationSnapshot = AuthorizationSnapshot(
            organizations: organizations,
            activeOrgSession: activeOrgSession,
            generatedAt: Date()
        )
    }

    private func inferOrganizationsFromClaims() -> [Organization] {
        let claims = jwtClaims()
        var inferred: [Organization] = []

        if let orgId = activeOrgSession?.workosOrganizationId ?? userInfo?.org_id ?? stringClaim(in: claims, keys: ["organization_id", "org_id"]) {
            inferred.append(
                Organization(
                    id: orgId,
                    workosOrgId: orgId,
                    name: stringClaim(in: claims, keys: ["organization_name", "org_name"]) ?? "Organization",
                    slug: stringClaim(in: claims, keys: ["organization_slug", "org_slug"]),
                    workosResourceId: stringClaim(in: claims, keys: ["organization_resource_id", "workos_resource_id"]),
                    externalId: orgId
                )
            )
        }

        if inferred.isEmpty, let existing = organizations.first {
            inferred.append(existing)
        }

        return inferred
    }

    private func inferFallbackSession(organizations: [Organization]) -> OrgSession? {
        let claims = jwtClaims()
        let org = organizations.first ?? self.organizations.first
        guard let org else { return nil }

        let permissions = inferredPermissions(from: claims)
        let roles = inferredRoleSlugs(from: claims)

        return OrgSession(
            orgId: org.id,
            workosOrganizationId: org.workosOrgId,
            organizationMembershipId: inferredMembershipId(from: claims),
            role: roles.first ?? "member",
            permissions: permissions,
            organizationRoles: roles,
            selectedResource: activeOrgSession?.selectedResource,
            accessibleResources: activeOrgSession?.accessibleResources ?? [],
            resourcePermissions: activeOrgSession?.resourcePermissions ?? [:],
            roleAssignments: activeOrgSession?.roleAssignments ?? [],
            lastRefreshedAt: Date()
        )
    }

    private func mergeOrganizations(existing: [Organization], with organization: Organization) -> [Organization] {
        var merged = existing.filter { $0.id != organization.id }
        merged.append(organization)
        return merged
    }

    private func inferredMembershipId() -> String? {
        inferredMembershipId(from: jwtClaims())
    }

    private func inferredMembershipId(from claims: [String: Any]) -> String? {
        stringClaim(in: claims, keys: ["organization_membership_id", "org_membership_id", "membership_id"])
    }

    private func inferredRoleSlugs() -> [String] {
        inferredRoleSlugs(from: jwtClaims())
    }

    private func inferredRoleSlugs(from claims: [String: Any]) -> [String] {
        var values = stringArrayClaim(in: claims, keys: ["user_roles", "roles", "role_slugs", "organization_roles"])

        if let userRole = stringClaim(in: claims, keys: ["user_role", "app_role"]), !userRole.isEmpty {
            values.insert(userRole, at: 0)
        }

        if let role = stringClaim(in: claims, keys: ["role", "organization_role"]),
           !role.isEmpty,
           !isTransportRole(role) {
            values.insert(role, at: 0)
        }

        if let authorization = claims["authorization"] as? [String: Any] {
            if let authorizationUserRole = stringClaim(in: authorization, keys: ["user_role", "app_role"]), !authorizationUserRole.isEmpty {
                values.insert(authorizationUserRole, at: 0)
            }

            if let authorizationRole = stringClaim(in: authorization, keys: ["role", "organization_role"]),
               !authorizationRole.isEmpty,
               !isTransportRole(authorizationRole) {
                values.insert(authorizationRole, at: 0)
            }

            values.append(contentsOf: stringArrayClaim(in: authorization, keys: ["user_roles", "roles", "organization_roles"]))
        }

        return Array(NSOrderedSet(array: values)) as? [String] ?? values
    }

    private func inferredPermissions() -> Set<Permission> {
        inferredPermissions(from: jwtClaims())
    }

    private func inferredPermissions(from claims: [String: Any]) -> Set<Permission> {
        var values = stringArrayClaim(in: claims, keys: ["permissions", "permission_slugs", "org_permissions"])

        if let authorization = claims["authorization"] as? [String: Any] {
            values.append(contentsOf: stringArrayClaim(in: authorization, keys: ["permissions", "permission_slugs"]))
        }

        return Set(values.map(Permission.init(rawValue:)))
    }

    private func deduplicatedRoleSlugs(_ values: [String]) -> [String] {
        let normalized = values
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        return Array(NSOrderedSet(array: normalized)) as? [String] ?? normalized
    }

    private func isTransportRole(_ role: String) -> Bool {
        switch role.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "authenticated", "anon", "anonymous", "service_role":
            return true
        default:
            return false
        }
    }

    private func jwtClaims() -> [String: Any] {
        if let tokens, let claims = decodeJWTClaims(from: tokens.idToken) ?? decodeJWTClaims(from: tokens.accessToken) {
            return claims
        }
        return [:]
    }

    private func decodeJWTClaims(from jwt: String) -> [String: Any]? {
        guard let payloadData = decodeJWTPayload(jwt) else { return nil }
        return (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
    }

    private func decodeJWTPayload(_ jwt: String) -> Data? {
        let segments = jwt.split(separator: ".")
        guard segments.count == 3 else { return nil }

        var base64 = String(segments[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))

        return Data(base64Encoded: base64)
    }

    private func stringClaim(in dictionary: [String: Any], keys: [String]) -> String? {
        for key in keys {
            if let value = dictionary[key] as? String, !value.isEmpty {
                return value
            }
        }
        return nil
    }

    private func stringArrayClaim(in dictionary: [String: Any], keys: [String]) -> [String] {
        var results: [String] = []
        for key in keys {
            if let values = dictionary[key] as? [String] {
                results.append(contentsOf: values)
            } else if let nested = dictionary[key] as? [[String: Any]] {
                for object in nested {
                    if let slug = object["slug"] as? String {
                        results.append(slug)
                    }
                }
            }
        }
        return results
    }

    // MARK: - Logging

    private func log(_ message: String) {
        WorkOSLogger.log("[AuthStore] \(message)")
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
    let organizationMembershipId: String?
    let organizations: [Organization]
    let authorizationSnapshot: AuthorizationSnapshot?
    let lastAuthenticatedAt: Date
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
