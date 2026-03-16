import Foundation

/// Extension providing permission check hooks on AuthStore.
extension AuthStore {

    // MARK: - Permission Checks

    /// Check if user has a specific permission in the active org.
    public func has(_ permission: Permission) -> Bool {
        has(permission, in: activeOrgSession?.selectedResource)
    }

    /// Check if user has a specific permission in a resource context.
    public func has(_ permission: Permission, in resource: AuthorizationResource?) -> Bool {
        guard let session = activeOrgSession else { return false }
        return session.permissions(for: resource).contains(permission)
    }

    /// Check if user has any of the specified permissions.
    public func hasAny(_ permissions: Permission...) -> Bool {
        permissions.contains { has($0) }
    }

    /// Check if user has all of the specified permissions.
    public func hasAll(_ permissions: Permission...) -> Bool {
        permissions.allSatisfy { has($0) }
    }

    /// Require a permission, throwing if not present.
    public func require(_ permission: Permission) throws {
        guard has(permission) else {
            throw PermissionError.denied(permission)
        }
    }

    /// Require multiple permissions.
    public func requireAll(_ permissions: Permission...) throws {
        for permission in permissions {
            guard has(permission) else {
                throw PermissionError.denied(permission)
            }
        }
    }

    // MARK: - Role Checks

    /// Check if user has a specific role.
    public func hasRole(_ role: String) -> Bool {
        guard let session = activeOrgSession else { return false }
        return session.role == role || session.organizationRoles.contains(role)
    }

    /// Check if user has any of the specified roles.
    public func hasAnyRole(_ roles: String...) -> Bool {
        roles.contains { hasRole($0) }
    }

    // MARK: - Convenience Properties

    /// Whether user is an owner.
    public var isOwner: Bool {
        hasRole("owner")
    }

    /// Whether user is an admin.
    public var isAdmin: Bool {
        hasAnyRole("owner", "admin")
    }

    /// Whether user can manage members.
    public var canManageMembers: Bool {
        hasAny(.membersInvite, .membersRemove, .membersManageRoles)
    }

    /// Whether user can manage billing.
    public var canManageBilling: Bool {
        has(.billingManage)
    }

    /// Whether user can view audit logs.
    public var canViewAudit: Bool {
        has(.auditRead)
    }

    // MARK: - Conditional Execution

    /// Execute a closure only if user has permission.
    public func ifHas(_ permission: Permission, execute: () -> Void) {
        if has(permission) {
            execute()
        }
    }

    /// Execute a closure only if user has permission (async version).
    public func ifHas(_ permission: Permission, execute: () async throws -> Void) async rethrows {
        if has(permission) {
            try await execute()
        }
    }
}
