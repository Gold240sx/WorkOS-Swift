import Foundation
import AuthenticationServices
#if canImport(UIKit)
import UIKit
#endif

/// Controller for handling WorkOS OAuth authentication flow.
public final class WorkOSAuthController: NSObject, Sendable {
    private let configuration: WorkOSConfiguration

    // Use actor for thread-safe state management
    private actor AuthState {
        var session: ASWebAuthenticationSession?
        var pkce: PKCE?
        var continuation: CheckedContinuation<AuthResult, Error>?

        func setSession(_ session: ASWebAuthenticationSession?) {
            self.session = session
        }

        func setPKCE(_ pkce: PKCE?) {
            self.pkce = pkce
        }

        func setContinuation(_ cont: CheckedContinuation<AuthResult, Error>?) {
            self.continuation = cont
        }

        func getPKCE() -> PKCE? {
            pkce
        }

        func getContinuation() -> CheckedContinuation<AuthResult, Error>? {
            continuation
        }

        func cancel() {
            session?.cancel()
            session = nil
            continuation?.resume(throwing: AuthError.userCancelled)
            continuation = nil
        }
    }

    private let authState = AuthState()

    public init(configuration: WorkOSConfiguration) {
        self.configuration = configuration
        super.init()
    }

    // MARK: - Sign In

    /// Start the OAuth sign-in flow.
    @MainActor
    public func signIn() async throws -> AuthResult {
        let pkce = PKCE.generate()
        await authState.setPKCE(pkce)

        guard let authUrl = configuration.authorizationUrl(pkce: pkce) else {
            throw AuthError.configurationError("Invalid authorization URL")
        }

        print("[WorkOS] Starting auth with URL: \(authUrl)")
        print("[WorkOS] Callback scheme: \(configuration.callbackScheme)")

        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authUrl,
                callbackURLScheme: configuration.callbackScheme
            ) { [weak self] callbackURL, error in
                guard let self = self else {
                    print("[WorkOS] Self was nil in callback")
                    return
                }

                Task {
                    if let error = error {
                        print("[WorkOS] Auth session error: \(error)")
                        if let authError = error as? ASWebAuthenticationSessionError {
                            if authError.code == .canceledLogin {
                                continuation.resume(throwing: AuthError.userCancelled)
                            } else {
                                continuation.resume(throwing: AuthError.networkError(authError.localizedDescription))
                            }
                        } else {
                            continuation.resume(throwing: AuthError.networkError(error.localizedDescription))
                        }
                        return
                    }

                    guard let callbackURL = callbackURL else {
                        print("[WorkOS] No callback URL received")
                        continuation.resume(throwing: AuthError.invalidResponse)
                        return
                    }

                    print("[WorkOS] Received callback URL: \(callbackURL)")

                    do {
                        let result = try await self.handleCallback(callbackURL)
                        print("[WorkOS] Token exchange successful")
                        continuation.resume(returning: result)
                    } catch {
                        print("[WorkOS] Token exchange failed: \(error)")
                        continuation.resume(throwing: error)
                    }
                }
            }

            session.presentationContextProvider = self

            #if os(iOS)
            session.prefersEphemeralWebBrowserSession = false
            #endif

            Task {
                await authState.setSession(session)
            }

            session.start()
        }
    }

    /// Handle the OAuth callback URL.
    private func handleCallback(_ url: URL) async throws -> AuthResult {
        print("[WorkOS] Handling callback: \(url)")

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            print("[WorkOS] Failed to parse callback URL")
            throw AuthError.invalidResponse
        }

        print("[WorkOS] Query items: \(components.queryItems ?? [])")

        // Check for error in callback
        if let error = components.queryItems?.first(where: { $0.name == "error" })?.value {
            let errorDesc = components.queryItems?.first(where: { $0.name == "error_description" })?.value ?? "Unknown error"
            print("[WorkOS] Auth error from WorkOS: \(error) - \(errorDesc)")
            throw AuthError.networkError("\(error): \(errorDesc)")
        }

        guard let code = components.queryItems?.first(where: { $0.name == "code" })?.value else {
            print("[WorkOS] No authorization code in callback")
            throw AuthError.invalidResponse
        }

        print("[WorkOS] Got authorization code: \(code.prefix(10))...")

        return try await exchangeCodeForTokens(code)
    }

    /// Exchange authorization code for tokens.
    private func exchangeCodeForTokens(_ code: String) async throws -> AuthResult {
        guard let pkce = await authState.getPKCE() else {
            throw AuthError.configurationError("PKCE verifier not found")
        }

        guard let tokenUrl = configuration.tokenUrl else {
            throw AuthError.configurationError("Invalid token URL")
        }

        var request = URLRequest(url: tokenUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // WorkOS expects JSON body for /user_management/authenticate
        let bodyDict: [String: Any] = [
            "grant_type": "authorization_code",
            "client_id": configuration.clientId,
            "code": code,
            "code_verifier": pkce.verifier
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: bodyDict)

        print("[WorkOS] Exchanging code at: \(tokenUrl)")

        let (data, response) = try await URLSession.shared.data(for: request)

        // Log raw response for debugging
        let rawResponse = String(data: data, encoding: .utf8) ?? "Unable to decode response"
        print("[WorkOS] Raw response: \(rawResponse)")

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.networkError("Invalid response")
        }

        if !(200...299).contains(httpResponse.statusCode) {
            print("[WorkOS] Token exchange failed (\(httpResponse.statusCode)): \(rawResponse)")
            throw AuthError.networkError("Token exchange failed (\(httpResponse.statusCode)): \(rawResponse)")
        }

        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        return AuthResult(tokens: tokenResponse.toAuthTokens(), userInfo: tokenResponse.toUserInfo())
    }

    // MARK: - Token Refresh

    /// Refresh authentication tokens.
    public func refreshTokens(refreshToken: String) async throws -> AuthTokens {
        guard let tokenUrl = configuration.tokenUrl else {
            throw AuthError.configurationError("Invalid token URL")
        }

        var request = URLRequest(url: tokenUrl)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let body = [
            "grant_type=refresh_token",
            "client_id=\(configuration.clientId)",
            "refresh_token=\(refreshToken)"
        ].joined(separator: "&")

        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw AuthError.tokenRefreshFailed
        }

        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        return tokenResponse.toAuthTokens()
    }

    // MARK: - Cancel

    /// Cancel any in-progress authentication.
    public func cancel() async {
        await authState.cancel()
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension WorkOSAuthController: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(iOS)
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
        #else
        return NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #endif
    }
}
