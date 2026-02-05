import SwiftUI

/// Protocol for admin backend API.
public protocol AdminAPI: Sendable {
    func fetchMembers(orgId: String) async throws -> [OrgMember]
    func fetchRoles(orgId: String) async throws -> [OrgRole]
    func updateRole(orgId: String, userId: String, roleId: String) async throws
    func fetchAuditLogs(orgId: String) async throws -> [AuditLog]
}

// MARK: - Admin Dashboard

/// Main admin dashboard view.
public struct AdminDashboardView: View {
    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme

    let api: AdminAPI

    public init(api: AdminAPI) {
        self.api = api
    }

    public var body: some View {
        List {
            if auth.has(.membersRead) {
                NavigationLink {
                    MembersAdminView(api: api)
                } label: {
                    Label("Members", systemImage: "person.3")
                }
            }

            if auth.has(.orgManage) {
                NavigationLink {
                    RolesView(api: api)
                } label: {
                    Label("Roles", systemImage: "shield")
                }
            }

            if auth.has(.auditRead) {
                NavigationLink {
                    AuditLogViewContainer(api: api)
                } label: {
                    Label("Audit Logs", systemImage: "list.bullet.clipboard")
                }
            }
        }
        .navigationTitle("Admin")
    }
}

// MARK: - Members Admin View

/// View for managing organization members.
public struct MembersAdminView: View {
    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme

    let api: AdminAPI

    @State private var members: [OrgMember] = []
    @State private var isLoading = true
    @State private var error: Error?

    public init(api: AdminAPI) {
        self.api = api
    }

    public var body: some View {
        Group {
            if isLoading {
                ProgressView()
            } else if let error = error {
                VStack(spacing: theme.spacing) {
                    Text("Error loading members")
                        .font(.headline)
                    Text(error.localizedDescription)
                        .foregroundColor(theme.secondaryTextColor)
                    Button("Retry") {
                        Task { await loadMembers() }
                    }
                }
            } else {
                List(members) { member in
                    NavigationLink {
                        RoleAssignmentView(member: member, api: api)
                    } label: {
                        MemberRow(member: member)
                    }
                }
            }
        }
        .navigationTitle("Members")
        .task {
            await loadMembers()
        }
    }

    private func loadMembers() async {
        guard let orgId = auth.activeOrgSession?.orgId else { return }

        isLoading = true
        error = nil

        do {
            members = try await api.fetchMembers(orgId: orgId)
        } catch {
            self.error = error
        }

        isLoading = false
    }
}

/// Member row component.
struct MemberRow: View {
    let member: OrgMember
    @Environment(\.adminTheme) var theme

    var body: some View {
        HStack(spacing: theme.spacing) {
            Circle()
                .fill(theme.secondaryColor.opacity(0.2))
                .frame(width: 40, height: 40)
                .overlay {
                    Text(String(member.displayName.prefix(1)).uppercased())
                        .font(.headline)
                        .foregroundColor(theme.primaryColor)
                }

            VStack(alignment: .leading, spacing: 4) {
                Text(member.displayName)
                    .font(.body)
                Text(member.email)
                    .font(.caption)
                    .foregroundColor(theme.secondaryTextColor)
            }

            Spacer()

            Text(member.roleId.capitalized)
                .font(.caption)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(theme.secondaryColor.opacity(0.1))
                .cornerRadius(theme.cornerRadius / 2)
        }
    }
}

// MARK: - Role Assignment View

/// View for assigning roles to a member.
public struct RoleAssignmentView: View {
    let member: OrgMember
    let api: AdminAPI

    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme
    @Environment(\.dismiss) var dismiss

    @State private var roles: [OrgRole] = []
    @State private var selectedRole: String
    @State private var isLoading = false
    @State private var isSaving = false

    public init(member: OrgMember, api: AdminAPI) {
        self.member = member
        self.api = api
        _selectedRole = State(initialValue: member.roleId)
    }

    public var body: some View {
        Form {
            Section("Current Role") {
                Text(member.roleId.capitalized)
                    .foregroundColor(theme.secondaryTextColor)
            }

            Section("Change Role") {
                if isLoading {
                    ProgressView()
                } else {
                    Picker("Role", selection: $selectedRole) {
                        ForEach(roles) { role in
                            Text(role.name.capitalized).tag(role.id)
                        }
                    }
                    .pickerStyle(.inline)
                }
            }

            if auth.has(.membersManageRoles) {
                Section {
                    Button("Update Role") {
                        Task { await updateRole() }
                    }
                    .disabled(selectedRole == member.roleId || isSaving)
                    .foregroundColor(theme.primaryColor)
                }
            }
        }
        .navigationTitle(member.displayName)
        .task {
            await loadRoles()
        }
        .overlay {
            if isSaving {
                ProgressView()
                    .padding()
                    .background(theme.surfaceColor)
                    .cornerRadius(theme.cornerRadius)
            }
        }
    }

    private func loadRoles() async {
        guard let orgId = auth.activeOrgSession?.orgId else { return }

        isLoading = true
        do {
            roles = try await api.fetchRoles(orgId: orgId)
        } catch {
            // Handle error
        }
        isLoading = false
    }

    private func updateRole() async {
        guard let orgId = auth.activeOrgSession?.orgId else { return }

        isSaving = true
        do {
            try await api.updateRole(orgId: orgId, userId: member.id, roleId: selectedRole)
            await auth.refreshOrgSession()
            dismiss()
        } catch {
            // Handle error
        }
        isSaving = false
    }
}

// MARK: - Roles View

/// View for displaying organization roles.
public struct RolesView: View {
    let api: AdminAPI

    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme

    @State private var roles: [OrgRole] = []
    @State private var isLoading = true

    public init(api: AdminAPI) {
        self.api = api
    }

    public var body: some View {
        Group {
            if isLoading {
                ProgressView()
            } else {
                List(roles) { role in
                    RoleRow(role: role, theme: theme)
                }
            }
        }
        .navigationTitle("Roles")
        .task {
            await loadRoles()
        }
    }

    private func loadRoles() async {
        guard let orgId = auth.activeOrgSession?.orgId else { return }

        isLoading = true
        do {
            roles = try await api.fetchRoles(orgId: orgId)
        } catch {
            // Handle error
        }
        isLoading = false
    }
}

/// Role row component.
struct RoleRow: View {
    let role: OrgRole
    let theme: AdminTheme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing / 2) {
            HStack {
                Text(role.name.capitalized)
                    .font(.headline)

                if role.isDefault {
                    Text("Default")
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(theme.primaryColor.opacity(0.1))
                        .foregroundColor(theme.primaryColor)
                        .cornerRadius(4)
                }
            }

            if let description = role.description {
                Text(description)
                    .font(.caption)
                    .foregroundColor(theme.secondaryTextColor)
            }

            FlowLayout(spacing: 4) {
                ForEach(role.permissions, id: \.self) { permission in
                    Text(permission.rawValue)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(theme.secondaryColor.opacity(0.1))
                        .cornerRadius(4)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Audit Log Views

/// Container for audit log view.
public struct AuditLogViewContainer: View {
    let api: AdminAPI

    @EnvironmentObject var auth: AuthStore

    @State private var logs: [AuditLog] = []
    @State private var isLoading = true
    @State private var error: Error?

    public init(api: AdminAPI) {
        self.api = api
    }

    public var body: some View {
        Group {
            if isLoading {
                ProgressView()
            } else if let error = error {
                VStack {
                    Text("Error loading audit logs")
                    Text(error.localizedDescription)
                        .foregroundColor(.secondary)
                }
            } else {
                AuditLogView(logs: logs)
            }
        }
        .navigationTitle("Audit Logs")
        .task {
            await loadLogs()
        }
    }

    private func loadLogs() async {
        guard let orgId = auth.activeOrgSession?.orgId else { return }

        isLoading = true
        error = nil

        do {
            logs = try await api.fetchAuditLogs(orgId: orgId)
        } catch {
            self.error = error
        }

        isLoading = false
    }
}

/// Audit log list view.
public struct AuditLogView: View {
    let logs: [AuditLog]

    @Environment(\.adminTheme) var theme

    public init(logs: [AuditLog]) {
        self.logs = logs
    }

    public var body: some View {
        List(logs) { log in
            VStack(alignment: .leading, spacing: 4) {
                Text(log.actionDescription)
                    .font(.headline)

                if let metadata = log.metadata {
                    ForEach(metadata.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                        Text("\(key): \(value)")
                            .font(.caption)
                            .foregroundColor(theme.secondaryTextColor)
                    }
                }

                Text(log.createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.footnote)
                    .foregroundColor(theme.secondaryTextColor)
            }
            .padding(.vertical, 4)
        }
    }
}

// MARK: - Permission Guard View

/// View that only renders content if user has permission.
public struct RequiresPermission<Content: View>: View {
    let permission: Permission
    let content: () -> Content

    @EnvironmentObject var auth: AuthStore

    public init(
        _ permission: Permission,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.permission = permission
        self.content = content
    }

    public var body: some View {
        if auth.has(permission) {
            content()
        }
    }
}

// MARK: - Helper Views

/// Simple flow layout for tags.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        var result = CGSize.zero
        var currentX: CGFloat = 0
        var currentY: CGFloat = 0
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)

            if currentX + size.width > (proposal.width ?? .infinity) {
                currentX = 0
                currentY += lineHeight + spacing
                lineHeight = 0
            }

            currentX += size.width + spacing
            lineHeight = max(lineHeight, size.height)
            result.width = max(result.width, currentX)
            result.height = currentY + lineHeight
        }

        return result
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var currentX: CGFloat = bounds.minX
        var currentY: CGFloat = bounds.minY
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)

            if currentX + size.width > bounds.maxX {
                currentX = bounds.minX
                currentY += lineHeight + spacing
                lineHeight = 0
            }

            subview.place(at: CGPoint(x: currentX, y: currentY), proposal: .unspecified)
            currentX += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
    }
}
