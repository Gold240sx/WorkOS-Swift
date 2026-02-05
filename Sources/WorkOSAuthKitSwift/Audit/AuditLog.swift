import Foundation

/// Audit log entry representing a tracked action.
public struct AuditLog: Identifiable, Codable, Sendable {
    public let id: String
    public let action: String
    public let actorUserId: String?
    public let actorType: ActorType
    public let targetType: String?
    public let targetId: String?
    public let orgId: String?
    public let metadata: [String: String]?
    public let ipAddress: String?
    public let userAgent: String?
    public let createdAt: Date

    public init(
        id: String,
        action: String,
        actorUserId: String? = nil,
        actorType: ActorType = .user,
        targetType: String? = nil,
        targetId: String? = nil,
        orgId: String? = nil,
        metadata: [String: String]? = nil,
        ipAddress: String? = nil,
        userAgent: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.action = action
        self.actorUserId = actorUserId
        self.actorType = actorType
        self.targetType = targetType
        self.targetId = targetId
        self.orgId = orgId
        self.metadata = metadata
        self.ipAddress = ipAddress
        self.userAgent = userAgent
        self.createdAt = createdAt
    }

    /// Human-readable action description.
    public var actionDescription: String {
        switch action {
        case "org.member.added":
            return "Member added"
        case "org.member.removed":
            return "Member removed"
        case "org.role.changed":
            let previousRole = metadata?["previous_role"] ?? "unknown"
            let newRole = metadata?["new_role"] ?? "unknown"
            return "Role changed from \(previousRole) to \(newRole)"
        case "org.role.assigned":
            return "Role assigned"
        case "org.role.revoked":
            return "Role revoked"
        case "org.permissions.updated":
            return "Permissions updated"
        default:
            return action
        }
    }
}

/// Type of actor that performed an action.
public enum ActorType: String, Codable, Sendable {
    case user
    case system
    case api
}

/// Client for fetching audit logs.
public actor AuditClient {
    private let baseUrl: String
    private weak var authStore: AuthStore?

    public init(baseUrl: String, authStore: AuthStore) {
        self.baseUrl = baseUrl
        self.authStore = authStore
    }

    /// Fetch audit logs for an organization.
    public func fetchLogs(
        orgId: String,
        limit: Int = 100,
        action: String? = nil
    ) async throws -> [AuditLog] {
        guard let authStore = authStore else {
            throw AuthError.notAuthenticated
        }

        let token = try await authStore.validAccessToken()

        var urlComponents = URLComponents(string: "\(baseUrl)/orgs/\(orgId)/audit-logs")
        var queryItems: [URLQueryItem] = [
            URLQueryItem(name: "limit", value: String(limit))
        ]
        if let action = action {
            queryItems.append(URLQueryItem(name: "action", value: action))
        }
        urlComponents?.queryItems = queryItems

        guard let url = urlComponents?.url else {
            throw AuthError.configurationError("Invalid audit logs URL")
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw AuthError.networkError("Failed to fetch audit logs")
        }

        return try JSONDecoder().decode([AuditLog].self, from: data)
    }
}
