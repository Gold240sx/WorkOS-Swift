import Foundation

/// Permission types for role-based access control.
public enum Permission: String, Codable, Hashable, CaseIterable, Sendable {
    // Organization permissions
    case orgRead = "org:read"
    case orgManage = "org:manage"
    case orgDelete = "org:delete"

    // Member permissions
    case membersRead = "members:read"
    case membersInvite = "members:invite"
    case membersRemove = "members:remove"
    case membersManageRoles = "members:manage_roles"

    // Billing permissions
    case billingRead = "billing:read"
    case billingManage = "billing:manage"

    // Project permissions
    case projectsCreate = "projects:create"
    case projectsRead = "projects:read"
    case projectsUpdate = "projects:update"
    case projectsDelete = "projects:delete"

    // Audit permissions
    case auditRead = "audit:read"

    /// Human-readable display name.
    public var displayName: String {
        switch self {
        case .orgRead: return "View Organization"
        case .orgManage: return "Manage Organization"
        case .orgDelete: return "Delete Organization"
        case .membersRead: return "View Members"
        case .membersInvite: return "Invite Members"
        case .membersRemove: return "Remove Members"
        case .membersManageRoles: return "Manage Roles"
        case .billingRead: return "View Billing"
        case .billingManage: return "Manage Billing"
        case .projectsCreate: return "Create Projects"
        case .projectsRead: return "View Projects"
        case .projectsUpdate: return "Update Projects"
        case .projectsDelete: return "Delete Projects"
        case .auditRead: return "View Audit Logs"
        }
    }

    /// Category for grouping in UI.
    public var category: String {
        switch self {
        case .orgRead, .orgManage, .orgDelete:
            return "Organization"
        case .membersRead, .membersInvite, .membersRemove, .membersManageRoles:
            return "Members"
        case .billingRead, .billingManage:
            return "Billing"
        case .projectsCreate, .projectsRead, .projectsUpdate, .projectsDelete:
            return "Projects"
        case .auditRead:
            return "Audit"
        }
    }
}

/// Permission error type.
public enum PermissionError: Error, Sendable {
    case denied(Permission)
    case insufficientRole(required: String, actual: String)
}
