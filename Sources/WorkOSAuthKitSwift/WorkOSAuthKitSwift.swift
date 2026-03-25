import Foundation
import SwiftUI
#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

/// WorkOSAuthKitSwift - Enterprise authentication for Swift apps.
///
/// This SDK provides a complete authentication solution integrated with WorkOS:
/// - OAuth 2.0 PKCE flow with ASWebAuthenticationSession
/// - Sign in with Apple via WorkOS
/// - Token refresh and management
/// - Biometric unlock (Face ID / Touch ID)
/// - Offline session restoration
/// - Multi-organization support
/// - Role-based permissions with hooks
/// - Audit logging
/// - White-labeled admin UI
///
/// ## Quick Start
///
/// ```swift
/// // 1. Configure
/// let config = WorkOSConfiguration(
///     clientId: "YOUR_CLIENT_ID",
///     redirectUri: "yourapp://auth/callback"
/// )
///
/// // 2. Create auth store
/// let authStore = AuthStore(configuration: config)
///
/// // 3. Bootstrap on app launch
/// await authStore.bootstrap()
///
/// // 4. Use in SwiftUI
/// @main
/// struct MyApp: App {
///     @StateObject var auth = AuthStore(configuration: config)
///
///     var body: some Scene {
///         WindowGroup {
///             switch auth.state {
///             case .loading:
///                 ProgressView()
///             case .authenticated:
///                 MainView()
///             case .unauthenticated:
///                 LoginView()
///             }
///         }
///         .environmentObject(auth)
///     }
/// }
/// ```

// MARK: - Main Entry Point

/// Main entry point for WorkOS AuthKit.
public final class WorkOSAuthKit: Sendable {
    /// Shared instance (configure before use).
    public static var shared: WorkOSAuthKit?

    /// The auth store instance.
    public let authStore: AuthStore

    /// Initialize with configuration.
    @MainActor
    public init(configuration: WorkOSConfiguration) {
        self.authStore = AuthStore(configuration: configuration)
    }

    /// Configure the shared instance.
    @MainActor
    public static func configure(
        clientId: String,
        redirectUri: String,
        backendUrl: String? = nil,
        workosApiKey: String? = nil,
        debugLogging: Bool = false,
        maxOfflineDuration: OfflineSessionDuration = .days(7)
    ) {
        let config = WorkOSConfiguration(
            clientId: clientId,
            redirectUri: redirectUri,
            backendUrl: backendUrl,
            workosApiKey: workosApiKey,
            debugLogging: debugLogging,
            maxOfflineDuration: maxOfflineDuration
        )
        shared = WorkOSAuthKit(configuration: config)
    }
}

// MARK: - SwiftUI Environment

private struct AuthStoreKey: EnvironmentKey {
    static let defaultValue: AuthStore? = nil
}

extension EnvironmentValues {
    /// Access the AuthStore from the environment.
    public var authStore: AuthStore? {
        get { self[AuthStoreKey.self] }
        set { self[AuthStoreKey.self] = newValue }
    }
}

extension View {
    /// Inject the AuthStore into the environment.
    public func authStore(_ store: AuthStore) -> some View {
        environment(\.authStore, store)
            .environmentObject(store)
    }
}

// MARK: - Embedded Auth Session

/// Holds the PKCE state needed to complete an embedded (WKWebView) OAuth flow.
public struct EmbeddedAuthSession: Sendable {
    public let pkce: PKCE
    public let state: String
    public let callbackScheme: String
}

// MARK: - Login View

/// Pre-built login view.
public struct WorkOSLoginView: View {
    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme
    @Environment(\.colorScheme) var colorScheme

    private let forceAccountSelection: Bool
    @State private var isLoading = false
    @State private var isUnlocking = false
    @State private var error: String?

    public init(forceAccountSelection: Bool = false) {
        self.forceAccountSelection = forceAccountSelection
    }

    public var body: some View {
        VStack(spacing: theme.spacing * 2) {
            Spacer()

            // Logo placeholder
            Image(systemName: "person.circle.fill")
                .font(.system(size: 80))
                .foregroundColor(theme.primaryColor)

            Text("Welcome")
                .font(.largeTitle)
                .fontWeight(.bold)
                .foregroundStyle(.primary)

            Text("Sign in to continue")
                .foregroundStyle(.secondary)

            Spacer()

            if let error = error {
                Text(error)
                    .foregroundColor(theme.destructiveColor)
                    .font(.caption)
            }

            if auth.canUseBiometricUnlock {
                Button {
                    Task { await unlock() }
                } label: {
                    HStack {
                        if isUnlocking {
                            ProgressView()
                                .tint(theme.primaryColor)
                        } else {
                            Label("Unlock with Biometrics", systemImage: "faceid")
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(theme.surfaceColor)
                    .foregroundColor(theme.primaryColor)
                    .cornerRadius(theme.cornerRadius)
                }
                .disabled(isLoading || isUnlocking)
            }

            Button {
                Task { await signIn() }
            } label: {
                HStack {
                    if isLoading {
                        ProgressView()
                            .tint(.white)
                    } else {
                        Text("Sign In")
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(theme.primaryColor)
                .foregroundColor(.white)
                .cornerRadius(theme.cornerRadius)
            }
            .disabled(isLoading || isUnlocking)

            Spacer()
                .frame(height: theme.spacing * 2)
        }
        .padding(theme.spacing * 2)
        .background(adaptiveBackground)
    }

    private var adaptiveBackground: Color {
        #if canImport(AppKit)
        return Color(nsColor: .windowBackgroundColor)
        #elseif canImport(UIKit)
        return Color(uiColor: .systemBackground)
        #else
        return colorScheme == .dark ? Color(white: 0.12) : Color(white: 0.97)
        #endif
    }

    private func signIn() async {
        isLoading = true
        error = nil

        do {
            try await auth.signIn(forceAccountSelection: forceAccountSelection)
        } catch AuthError.userCancelled {
            // User cancelled, do nothing
        } catch {
            self.error = error.localizedDescription
        }

        isLoading = false
    }

    private func unlock() async {
        isUnlocking = true
        error = nil

        do {
            try await auth.unlockWithBiometrics()
        } catch {
            self.error = error.localizedDescription
        }

        isUnlocking = false
    }
}

// MARK: - Organization Picker

/// Pre-built organization picker.
public struct OrgPickerView: View {
    @EnvironmentObject var auth: AuthStore
    @Environment(\.adminTheme) var theme

    public init() {}

    public var body: some View {
        Menu {
            ForEach(auth.organizations) { org in
                Button {
                    Task {
                        try? await auth.switchOrganization(to: org)
                    }
                } label: {
                    HStack {
                        Text(org.name)
                        if auth.activeOrgSession?.orgId == org.id {
                            Image(systemName: "checkmark")
                        }
                    }
                }
            }
        } label: {
            Label("Organization", systemImage: "building.2")
        }
    }
}

// MARK: - Mock Support

#if DEBUG
extension AuthStore {
    /// Create a mock auth store for previews/testing.
    @MainActor
    public static func mock(
        state: AuthState = .authenticated,
        permissions: [Permission] = [],
        role: String = "member"
    ) -> AuthStore {
        let config = WorkOSConfiguration(
            clientId: "mock",
            redirectUri: "mock://callback"
        )
        let store = AuthStore(configuration: config)

        // Set mock state
        // Note: In production, use proper test helpers
        return store
    }
}
#endif

// MARK: - Type Aliases for Convenience

public typealias WorkOSConfig = WorkOSConfiguration
public typealias Auth = AuthStore
