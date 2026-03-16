import Foundation

/// Permission types for role-based access control.
public struct Permission: RawRepresentable, Codable, Hashable, Sendable, ExpressibleByStringLiteral, Identifiable {
    public let rawValue: String

    public var id: String { rawValue }

    public init(rawValue: String) {
        self.rawValue = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public init(stringLiteral value: String) {
        self.init(rawValue: value)
    }

    // Organization permissions
    public static let orgRead = Permission(rawValue: "org:read")
    public static let orgManage = Permission(rawValue: "org:manage")
    public static let orgDelete = Permission(rawValue: "org:delete")

    // Member permissions
    public static let membersRead = Permission(rawValue: "members:read")
    public static let membersInvite = Permission(rawValue: "members:invite")
    public static let membersRemove = Permission(rawValue: "members:remove")
    public static let membersManageRoles = Permission(rawValue: "members:manage_roles")

    // Billing permissions
    public static let billingRead = Permission(rawValue: "billing:read")
    public static let billingManage = Permission(rawValue: "billing:manage")

    // Project permissions
    public static let projectsCreate = Permission(rawValue: "projects:create")
    public static let projectsRead = Permission(rawValue: "projects:read")
    public static let projectsUpdate = Permission(rawValue: "projects:update")
    public static let projectsDelete = Permission(rawValue: "projects:delete")

    // Audit permissions
    public static let auditRead = Permission(rawValue: "audit:read")

    public static let knownDefaults: [Permission] = [
        .orgRead,
        .orgManage,
        .orgDelete,
        .membersRead,
        .membersInvite,
        .membersRemove,
        .membersManageRoles,
        .billingRead,
        .billingManage,
        .projectsCreate,
        .projectsRead,
        .projectsUpdate,
        .projectsDelete,
        .auditRead
    ]

    /// Human-readable display name.
    public var displayName: String {
        switch rawValue {
        case Self.orgRead.rawValue: return "View Organization"
        case Self.orgManage.rawValue: return "Manage Organization"
        case Self.orgDelete.rawValue: return "Delete Organization"
        case Self.membersRead.rawValue: return "View Members"
        case Self.membersInvite.rawValue: return "Invite Members"
        case Self.membersRemove.rawValue: return "Remove Members"
        case Self.membersManageRoles.rawValue: return "Manage Roles"
        case Self.billingRead.rawValue: return "View Billing"
        case Self.billingManage.rawValue: return "Manage Billing"
        case Self.projectsCreate.rawValue: return "Create Projects"
        case Self.projectsRead.rawValue: return "View Projects"
        case Self.projectsUpdate.rawValue: return "Update Projects"
        case Self.projectsDelete.rawValue: return "Delete Projects"
        case Self.auditRead.rawValue: return "View Audit Logs"
        default:
            return rawValue
                .replacingOccurrences(of: ":", with: " ")
                .replacingOccurrences(of: "_", with: " ")
                .split(separator: " ")
                .map { $0.capitalized }
                .joined(separator: " ")
        }
    }

    /// Category for grouping in UI.
    public var category: String {
        if let prefix = rawValue.split(separator: ":").first {
            return prefix
                .replacingOccurrences(of: "_", with: " ")
                .capitalized
        }
        return "General"
    }
}

/// Permission error type.
public enum PermissionError: Error, Sendable {
    case denied(Permission)
    case insufficientRole(required: String, actual: String)
}
