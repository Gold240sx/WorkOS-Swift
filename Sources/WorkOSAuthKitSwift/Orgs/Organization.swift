import Foundation

/// Represents an organization from WorkOS.
public struct Organization: Identifiable, Codable, Sendable {
    public let id: String
    public let workosOrgId: String
    public let name: String
    public let slug: String?
    public let workosResourceId: String?
    public let externalId: String?

    public init(
        id: String,
        workosOrgId: String,
        name: String,
        slug: String? = nil,
        workosResourceId: String? = nil,
        externalId: String? = nil
    ) {
        self.id = id
        self.workosOrgId = workosOrgId
        self.name = name
        self.slug = slug
        self.workosResourceId = workosResourceId
        self.externalId = externalId
    }
}

/// A WorkOS authorization resource exposed to the app.
public struct AuthorizationResource: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public let externalId: String?
    public let typeSlug: String
    public let name: String?
    public let parentResourceId: String?
    public let parentExternalId: String?

    public init(
        id: String,
        externalId: String? = nil,
        typeSlug: String,
        name: String? = nil,
        parentResourceId: String? = nil,
        parentExternalId: String? = nil
    ) {
        self.id = id
        self.externalId = externalId
        self.typeSlug = typeSlug
        self.name = name
        self.parentResourceId = parentResourceId
        self.parentExternalId = parentExternalId
    }
}

/// Resource-scoped role assignment.
public struct RoleAssignment: Identifiable, Codable, Hashable, Sendable {
    public let id: String
    public let roleSlug: String
    public let resource: AuthorizationResource

    public init(
        id: String,
        roleSlug: String,
        resource: AuthorizationResource
    ) {
        self.id = id
        self.roleSlug = roleSlug
        self.resource = resource
    }
}

/// Organization member information.
public struct OrgMember: Identifiable, Codable, Sendable {
    public let id: String
    public let email: String
    public let roleId: String
    public let firstName: String?
    public let lastName: String?
    public let profileImageUrl: String?
    public let organizationMembershipId: String?
    public let workosUserId: String?
    public let roleAssignments: [RoleAssignment]

    public init(
        id: String,
        email: String,
        roleId: String,
        firstName: String? = nil,
        lastName: String? = nil,
        profileImageUrl: String? = nil,
        organizationMembershipId: String? = nil,
        workosUserId: String? = nil,
        roleAssignments: [RoleAssignment] = []
    ) {
        self.id = id
        self.email = email
        self.roleId = roleId
        self.firstName = firstName
        self.lastName = lastName
        self.profileImageUrl = profileImageUrl
        self.organizationMembershipId = organizationMembershipId
        self.workosUserId = workosUserId
        self.roleAssignments = roleAssignments
    }

    public var displayName: String {
        if let first = firstName, let last = lastName {
            return "\(first) \(last)"
        }
        return email
    }

    public var roleSlug: String {
        roleId
    }
}

/// Role definition for an organization.
public struct OrgRole: Identifiable, Codable, Sendable {
    public let id: String
    public let slug: String
    public let name: String
    public let permissions: [Permission]
    public let description: String?
    public let isDefault: Bool
    public let resourceTypeSlug: String?

    public init(
        id: String,
        name: String,
        permissions: [Permission],
        description: String? = nil,
        isDefault: Bool = false,
        slug: String? = nil,
        resourceTypeSlug: String? = nil
    ) {
        self.id = id
        self.slug = slug ?? id
        self.name = name
        self.permissions = permissions
        self.description = description
        self.isDefault = isDefault
        self.resourceTypeSlug = resourceTypeSlug
    }
}

/// Active organization session with role and permissions.
public struct OrgSession: Codable, Sendable {
    public let orgId: String
    public let workosOrganizationId: String
    public let organizationMembershipId: String?
    public let role: String
    public let permissions: Set<Permission>
    public let organizationRoles: [String]
    public let selectedResource: AuthorizationResource?
    public let accessibleResources: [AuthorizationResource]
    public let resourcePermissions: [String: Set<Permission>]
    public let roleAssignments: [RoleAssignment]
    public let lastRefreshedAt: Date

    public init(
        orgId: String,
        workosOrganizationId: String? = nil,
        organizationMembershipId: String? = nil,
        role: String,
        permissions: Set<Permission>,
        organizationRoles: [String] = [],
        selectedResource: AuthorizationResource? = nil,
        accessibleResources: [AuthorizationResource] = [],
        resourcePermissions: [String: Set<Permission>] = [:],
        roleAssignments: [RoleAssignment] = [],
        lastRefreshedAt: Date = Date()
    ) {
        self.orgId = orgId
        self.workosOrganizationId = workosOrganizationId ?? orgId
        self.organizationMembershipId = organizationMembershipId
        self.role = role
        self.permissions = permissions
        self.organizationRoles = organizationRoles
        self.selectedResource = selectedResource
        self.accessibleResources = accessibleResources
        self.resourcePermissions = resourcePermissions
        self.roleAssignments = roleAssignments
        self.lastRefreshedAt = lastRefreshedAt
    }

    public func permissions(for resource: AuthorizationResource?) -> Set<Permission> {
        guard let resource else { return permissions }
        return resourcePermissions[resource.id] ?? permissions
    }

    public func selecting(resource: AuthorizationResource?) -> OrgSession {
        OrgSession(
            orgId: orgId,
            workosOrganizationId: workosOrganizationId,
            organizationMembershipId: organizationMembershipId,
            role: role,
            permissions: permissions,
            organizationRoles: organizationRoles,
            selectedResource: resource,
            accessibleResources: accessibleResources,
            resourcePermissions: resourcePermissions,
            roleAssignments: roleAssignments,
            lastRefreshedAt: lastRefreshedAt
        )
    }
}
