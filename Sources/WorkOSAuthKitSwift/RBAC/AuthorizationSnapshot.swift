import Foundation

/// Cached authorization state safe to persist offline.
public struct AuthorizationSnapshot: Codable, Sendable {
    public let organizations: [Organization]
    public let activeOrgSession: OrgSession?
    public let generatedAt: Date

    public init(
        organizations: [Organization],
        activeOrgSession: OrgSession?,
        generatedAt: Date = Date()
    ) {
        self.organizations = organizations
        self.activeOrgSession = activeOrgSession
        self.generatedAt = generatedAt
    }
}

/// Request payload for resource-scoped permission checks.
public struct PermissionCheckRequest: Codable, Sendable {
    public let permissionSlug: String
    public let resourceId: String?
    public let resourceExternalId: String?
    public let resourceTypeSlug: String?

    public init(
        permissionSlug: String,
        resourceId: String? = nil,
        resourceExternalId: String? = nil,
        resourceTypeSlug: String? = nil
    ) {
        self.permissionSlug = permissionSlug
        self.resourceId = resourceId
        self.resourceExternalId = resourceExternalId
        self.resourceTypeSlug = resourceTypeSlug
    }
}

public struct PermissionCheckResult: Codable, Sendable {
    public let authorized: Bool
}

public struct RoleAssignmentRequest: Codable, Sendable {
    public let roleSlug: String
    public let resourceId: String?
    public let resourceExternalId: String?
    public let resourceTypeSlug: String?

    public init(
        roleSlug: String,
        resourceId: String? = nil,
        resourceExternalId: String? = nil,
        resourceTypeSlug: String? = nil
    ) {
        self.roleSlug = roleSlug
        self.resourceId = resourceId
        self.resourceExternalId = resourceExternalId
        self.resourceTypeSlug = resourceTypeSlug
    }
}

struct ListResponse<T: Decodable>: Decodable {
    let data: [T]
}
