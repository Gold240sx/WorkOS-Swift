import Foundation

/// App-facing client for DevSpace RBAC operations backed by a privileged service.
public actor RBACClient: AdminAPI {
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

    public func listOrganizations() async throws -> [Organization] {
        try await perform(path: "/authz/organizations")
    }

    public func fetchAuthorizationSnapshot(organizationId: String? = nil) async throws -> AuthorizationSnapshot {
        var queryItems: [URLQueryItem] = []
        if let organizationId, !organizationId.isEmpty {
            queryItems.append(URLQueryItem(name: "organization_id", value: organizationId))
        }
        return try await perform(path: "/authz/authorization-snapshot", queryItems: queryItems)
    }

    public func listAccessibleResources(
        organizationMembershipId: String,
        permission: Permission,
        parent: AuthorizationResource? = nil
    ) async throws -> [AuthorizationResource] {
        var queryItems = [URLQueryItem(name: "permission_slug", value: permission.rawValue)]
        if let parent {
            if let externalId = parent.externalId, !externalId.isEmpty {
                queryItems.append(URLQueryItem(name: "parent_resource_external_id", value: externalId))
                queryItems.append(URLQueryItem(name: "parent_resource_type_slug", value: parent.typeSlug))
            } else {
                queryItems.append(URLQueryItem(name: "parent_resource_id", value: parent.id))
            }
        }

        let response: ListResponse<AuthorizationResource> = try await perform(
            path: "/authz/organization-memberships/\(organizationMembershipId)/resources",
            queryItems: queryItems
        )
        return response.data
    }

    public func checkPermission(
        organizationMembershipId: String,
        permission: Permission,
        resource: AuthorizationResource
    ) async throws -> Bool {
        let request = PermissionCheckRequest(
            permissionSlug: permission.rawValue,
            resourceId: resource.externalId == nil ? resource.id : nil,
            resourceExternalId: resource.externalId,
            resourceTypeSlug: resource.externalId == nil ? nil : resource.typeSlug
        )
        let result: PermissionCheckResult = try await perform(
            path: "/authz/organization-memberships/\(organizationMembershipId)/check",
            method: "POST",
            body: request
        )
        return result.authorized
    }

    public func assignRole(
        organizationMembershipId: String,
        roleSlug: String,
        resource: AuthorizationResource
    ) async throws -> RoleAssignment {
        let request = RoleAssignmentRequest(
            roleSlug: roleSlug,
            resourceId: resource.externalId == nil ? resource.id : nil,
            resourceExternalId: resource.externalId,
            resourceTypeSlug: resource.externalId == nil ? nil : resource.typeSlug
        )
        return try await perform(
            path: "/authz/organization-memberships/\(organizationMembershipId)/role-assignments",
            method: "POST",
            body: request
        )
    }

    public func removeRoleAssignment(
        organizationMembershipId: String,
        roleAssignmentId: String
    ) async throws {
        let _: EmptyResponse = try await perform(
            path: "/authz/organization-memberships/\(organizationMembershipId)/role-assignments/\(roleAssignmentId)",
            method: "DELETE"
        )
    }

    public func fetchMembers(orgId: String) async throws -> [OrgMember] {
        try await perform(path: "/authz/organizations/\(orgId)/members")
    }

    public func fetchRoles(orgId: String) async throws -> [OrgRole] {
        try await perform(path: "/authz/organizations/\(orgId)/roles")
    }

    public func updateRole(orgId: String, userId: String, roleId: String) async throws {
        let _: EmptyResponse = try await perform(
            path: "/authz/organizations/\(orgId)/members/\(userId)/role",
            method: "PUT",
            body: ["role_slug": roleId]
        )
    }

    public func fetchAuditLogs(orgId: String) async throws -> [AuditLog] {
        try await perform(path: "/authz/organizations/\(orgId)/audit-logs")
    }

    private func perform<Response: Decodable>(
        path: String,
        method: String = "GET",
        queryItems: [URLQueryItem] = [],
        body: (any Encodable)? = nil
    ) async throws -> Response {
        guard let url = configuration.rbacServiceURL(path: path, queryItems: queryItems) else {
            throw AuthError.configurationError("RBAC service URL not configured")
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let authStore {
            let token = try await authStore.validAccessToken()
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try encoder.encode(AnyEncodable(body))
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.invalidResponse
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let message = String(data: data, encoding: .utf8) ?? HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode)
            throw AuthError.networkError(message)
        }

        if Response.self == EmptyResponse.self {
            return EmptyResponse() as! Response
        }

        return try decoder.decode(Response.self, from: data)
    }
}

private struct EmptyResponse: Decodable {}

private struct AnyEncodable: Encodable {
    private let encodeImpl: (Encoder) throws -> Void

    init(_ wrapped: any Encodable) {
        self.encodeImpl = wrapped.encode(to:)
    }

    func encode(to encoder: Encoder) throws {
        try encodeImpl(encoder)
    }
}
