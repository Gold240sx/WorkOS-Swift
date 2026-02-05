<p align="center">
  <picture>
    <source srcset="https://utfs.io/f/8fef9f6b-af02-42c2-8e1f-a31fe685ae03-wc6ubf.svg" type="image/svg+xml" />
    <img src="https://utfs.io/f/bd3d5cad-5e86-42c4-9d22-cd5e4d7e6792-wc6ubf.png" alt="WorkOS-Swift" width="160" />
  </picture>
</p>

# WorkOS-Swift (WorkOSAuthKitSwift)

**Version 1.0.0**

A Swift package for [WorkOS](https://workos.com) AuthKit/User Management authentication in iOS and macOS apps (OAuth 2.0 PKCE via `ASWebAuthenticationSession`), with no external dependencies.

This package is **backend-agnostic**. If you use a backend to verify tokens, load organizations, or exchange org-scoped sessions, it can be anything (your own API, serverless functions, etc.). For example, you *can* implement these endpoints using **Convex HTTP Actions**, but Convex is not required.

## Overview

WorkOSAuthKitSwift brings WorkOS authentication to native Swift apps. Since WorkOS doesn't provide an official Swift SDK, this package implements the complete OAuth 2.0 PKCE flow with enterprise features like multi-organization support, RBAC, and biometric unlock.

## Features

- **OAuth 2.0 PKCE Flow** - Secure authentication via ASWebAuthenticationSession
- **Sign in with Apple** - Via WorkOS SSO integration
- **Token Management** - Automatic refresh with secure Keychain storage
- **Biometric Unlock** - Face ID / Touch ID for session restoration
- **Offline Sessions** - Restore auth state without network
- **Multi-Organization** - Switch between organizations seamlessly
- **Role-Based Access Control** - Permission checking with SwiftUI hooks
- **Audit Logging** - Track auth events for compliance
- **White-Label Admin UI** - Themeable user/org management views

## Requirements

- iOS 16.0+ / macOS 13.0+
- Swift 5.9+
- Xcode 15.0+
- WorkOS account with User Management enabled

## Installation

### Swift Package Manager

Add this package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Gold240sx/WorkOS-Swift.git", from: "1.0.0")
]
```

Or add it via Xcode:
1. File > Add Package Dependencies
2. Enter the package URL: `https://github.com/Gold240sx/WorkOS-Swift.git`
3. Select version: `1.0.0` (or “Up to Next Major”)

### Dependencies

This package has **no external dependencies** - it uses only Apple frameworks:
- `AuthenticationServices` - OAuth flow
- `Security` - Keychain storage
- `LocalAuthentication` - Biometrics
- `SwiftUI` - UI components

## Quick Start

### 1. Configure WorkOS

```swift
import WorkOSAuthKitSwift

let config = WorkOSConfiguration(
    clientId: "client_01ABC...",
    redirectUri: "yourapp://auth/callback",
    debugLogging: true,
    maxOfflineDuration: .days(7) // or .hours(12) / .minutes(30) / .never
)
```

### 2. Create AuthStore

```swift
@main
struct MyApp: App {
    @StateObject private var auth = AuthStore(
        configuration: WorkOSConfiguration(
            clientId: "client_01ABC...",
            redirectUri: "yourapp://auth/callback",
            maxOfflineDuration: .days(7)
        )
    )

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(auth)
                .task {
                    await auth.bootstrap()
                }
        }
    }
}
```

### 3. Handle Auth State

```swift
struct RootView: View {
    @EnvironmentObject var auth: AuthStore

    var body: some View {
        switch auth.state {
        case .loading:
            ProgressView("Loading...")
        case .unauthenticated:
            WorkOSLoginView()
        case .authenticated:
            MainAppView()
        }
    }
}
```

### 4. Configure Redirect URI + URL Scheme

In the WorkOS dashboard (AuthKit / User Management), add your redirect URI:

- `yourapp://auth/callback`

Then add the URL scheme (`yourapp`) to your app’s `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>yourapp</string>
    </array>
  </dict>
</array>
```

## Configuration

### Basic Configuration

```swift
let config = WorkOSConfiguration(
    clientId: "client_01ABC...",      // Your WorkOS client ID
    redirectUri: "myapp://callback"    // Must match WorkOS dashboard
)
```

### Full Configuration

```swift
let config = WorkOSConfiguration(
    clientId: "client_01ABC...",
    redirectUri: "myapp://callback",

    // Optional: Your backend (any stack) for token verification and org-scoped session exchange.
    // Example backends: your own API, serverless functions, or Convex HTTP Actions.
    backendUrl: "https://api.yourapp.com",

    // Optional: Custom WorkOS endpoints (rarely needed)
    apiBaseUrl: "https://api.workos.com",

    // Debug logging
    debugLogging: true,

    // Offline session policy
    maxOfflineDuration: .days(7)
)
```

### URL Scheme Setup

Add your callback URL scheme to your app's `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

## Authentication

### Sign In

```swift
// Using the built-in login view
WorkOSLoginView()

// Or programmatically
Button("Sign In") {
    Task {
        try await auth.signIn()
    }
}
```

### Sign Out

```swift
Button("Sign Out") {
    auth.signOut()
}
```

### Token Access

```swift
// Get current access token for API calls
if let token = auth.accessToken {
    var request = URLRequest(url: apiURL)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
}
```

## Multi-Organization Support

### List Organizations

```swift
ForEach(auth.organizations) { org in
    Text(org.name)
}
```

### Switch Organization

```swift
Button("Switch to \(org.name)") {
    Task {
        try await auth.switchOrganization(to: org)
    }
}
```

### Current Organization

```swift
if let session = auth.activeOrgSession {
    Text("Current: \(session.orgName)")
    Text("Role: \(session.role)")
}
```

### Organization Picker View

```swift
// Built-in picker
OrgPickerView()
```

## Role-Based Access Control

### Check Permissions

```swift
if auth.hasPermission("documents:write") {
    Button("Create Document") { ... }
}

// Or multiple permissions
if auth.hasAllPermissions(["documents:write", "documents:delete"]) {
    Button("Manage Documents") { ... }
}
```

### Permission Hooks in SwiftUI

```swift
struct DocumentView: View {
    @EnvironmentObject var auth: AuthStore

    var body: some View {
        VStack {
            // Always visible
            DocumentList()

            // Only if user can write
            if auth.hasPermission("documents:write") {
                CreateButton()
            }
        }
    }
}
```

### Define Permissions

```swift
extension Permission {
    static let documentsRead = Permission("documents:read")
    static let documentsWrite = Permission("documents:write")
    static let documentsDelete = Permission("documents:delete")
    static let adminAccess = Permission("admin:access")
}
```

## Biometric Authentication

### Enable Biometric Unlock

```swift
// After successful sign-in
try await auth.enableBiometricUnlock()
```

### Restore Session with Biometrics

```swift
// In bootstrap or on app foreground
if auth.canUseBiometricUnlock {
    try await auth.unlockWithBiometrics()
}
```

### Biometric UI

```swift
struct UnlockView: View {
    @EnvironmentObject var auth: AuthStore

    var body: some View {
        VStack {
            Image(systemName: "faceid")
                .font(.system(size: 60))

            Button("Unlock with Face ID") {
                Task {
                    try await auth.unlockWithBiometrics()
                }
            }
        }
    }
}
```

## Audit Logging

```swift
// Log custom events
auth.auditLog(
    action: "document.created",
    targetType: "document",
    targetId: documentId,
    metadata: ["title": document.title]
)

// View audit logs (admin)
ForEach(auth.auditLogs) { log in
    Text("\(log.action) at \(log.createdAt)")
}
```

## Theming

### Custom Theme

```swift
let theme = AdminTheme(
    primaryColor: .blue,
    backgroundColor: Color(.systemBackground),
    cardBackgroundColor: Color(.secondarySystemBackground),
    textColor: .primary,
    secondaryTextColor: .secondary,
    destructiveColor: .red,
    successColor: .green,
    cornerRadius: 12,
    spacing: 16
)

ContentView()
    .environment(\.adminTheme, theme)
```

### Dark Mode Support

The theme automatically adapts to system appearance when using semantic colors.

## Pre-Built Views

### WorkOSLoginView

Full-featured login screen with error handling:

```swift
WorkOSLoginView()
    .environmentObject(auth)
```

### OrgPickerView

Organization switcher menu:

```swift
OrgPickerView()
    .environmentObject(auth)
```

### UserManagementView (Admin)

User administration interface:

```swift
UserManagementView()
    .environmentObject(auth)
```

### OrganizationManagementView (Admin)

Organization administration:

```swift
OrganizationManagementView()
    .environmentObject(auth)
```

## API Reference

### AuthStore

| Property | Type | Description |
|----------|------|-------------|
| `state` | `AuthState` | Current auth state |
| `user` | `User?` | Authenticated user |
| `organizations` | `[Organization]` | User's organizations |
| `activeOrgSession` | `OrgSession?` | Current org context |
| `accessToken` | `String?` | Current access token |
| `permissions` | `[Permission]` | Active permissions |

| Method | Description |
|--------|-------------|
| `bootstrap()` | Initialize and restore session |
| `signIn()` | Start OAuth flow |
| `signOut()` | Clear session |
| `switchOrganization(to:)` | Change org context |
| `refreshTokensIfNeeded()` | Refresh expiring tokens |
| `hasPermission(_:)` | Check single permission |
| `hasAllPermissions(_:)` | Check multiple permissions |
| `enableBiometricUnlock()` | Enable biometric auth |
| `unlockWithBiometrics()` | Authenticate with biometrics |

### AuthState

```swift
public enum AuthState: Equatable {
    case loading
    case unauthenticated
    case authenticated
}
```

### AuthError

```swift
public enum AuthError: Error {
    case configurationError(String)
    case networkError(String)
    case invalidResponse
    case tokenRefreshFailed
    case userCancelled
    case biometricFailed
    case unauthorized
}
```

## Backend Integration

### Token Verification Endpoint

Your backend should verify tokens with WorkOS:

```typescript
// Convex http.ts example
http.route({
  path: "/auth/verify",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const { accessToken, idToken } = await request.json();

    // Verify with WorkOS or decode JWT
    const payload = JSON.parse(atob(idToken.split(".")[1]));

    // Upsert user in your database
    await ctx.runMutation(api.auth.upsertUser, {
      workosUserId: payload.sub,
      email: payload.email,
      // ...
    });

    return new Response(JSON.stringify({ success: true }));
  }),
});
```

## Changelog

### 1.0.0 (Initial Release)

- OAuth 2.0 PKCE authentication flow
- ASWebAuthenticationSession integration
- Secure Keychain token storage
- Biometric unlock support
- Multi-organization support
- Role-based permission checking
- Audit logging
- Pre-built SwiftUI views
- Themeable admin UI components

## Security Considerations

- Tokens are stored in the iOS/macOS Keychain with `kSecAttrAccessibleAfterFirstUnlock`
- PKCE is used for all OAuth flows (no client secret in mobile apps)
- Biometric data never leaves the device
- Refresh tokens are rotated on each use

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

## Related

- [WorkOS Documentation](https://workos.com/docs)
- [WorkOS User Management](https://workos.com/docs/user-management)
- [OAuth 2.0 PKCE](https://oauth.net/2/pkce/)
