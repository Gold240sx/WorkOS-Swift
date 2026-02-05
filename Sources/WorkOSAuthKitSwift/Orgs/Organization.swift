import Foundation

/// Represents an organization from WorkOS.
public struct Organization: Identifiable, Codable, Sendable {
    public let id: String
    public let workosOrgId: String
    public let name: String
    public let slug: String?

    public init(
        id: String,
        workosOrgId: String,
        name: String,
        slug: String? = nil
    ) {
        self.id = id
        self.workosOrgId = workosOrgId
        self.name = name
        self.slug = slug
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

    public init(
        id: String,
        email: String,
        roleId: String,
        firstName: String? = nil,
        lastName: String? = nil,
        profileImageUrl: String? = nil
    ) {
        self.id = id
        self.email = email
        self.roleId = roleId
        self.firstName = firstName
        self.lastName = lastName
        self.profileImageUrl = profileImageUrl
    }

    public var displayName: String {
        if let first = firstName, let last = lastName {
            return "\(first) \(last)"
        }
        return email
    }
}

/// Role definition for an organization.
public struct OrgRole: Identifiable, Codable, Sendable {
    public let id: String
    public let name: String
    public let permissions: [Permission]
    public let description: String?
    public let isDefault: Bool

    public init(
        id: String,
        name: String,
        permissions: [Permission],
        description: String? = nil,
        isDefault: Bool = false
    ) {
        self.id = id
        self.name = name
        self.permissions = permissions
        self.description = description
        self.isDefault = isDefault
    }
}

/// Active organization session with role and permissions.
public struct OrgSession: Codable, Sendable {
    public let orgId: String
    public let role: String
    public let permissions: Set<Permission>

    public init(orgId: String, role: String, permissions: Set<Permission>) {
        self.orgId = orgId
        self.role = role
        self.permissions = permissions
    }
}
