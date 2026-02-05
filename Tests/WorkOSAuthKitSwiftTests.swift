import XCTest
@testable import WorkOSAuthKitSwift

final class WorkOSAuthKitSwiftTests: XCTestCase {

    func testPKCEGeneration() {
        let pkce = PKCE.generate()

        XCTAssertEqual(pkce.verifier.count, 64)
        XCTAssertFalse(pkce.challenge.isEmpty)
        XCTAssertNotEqual(pkce.verifier, pkce.challenge)
    }

    func testPKCEChallengeIsBase64Url() {
        let pkce = PKCE.generate()

        // Base64URL should not contain +, /, or =
        XCTAssertFalse(pkce.challenge.contains("+"))
        XCTAssertFalse(pkce.challenge.contains("/"))
        XCTAssertFalse(pkce.challenge.contains("="))
    }

    func testConfigurationAuthorizationUrl() {
        let config = WorkOSConfiguration(
            clientId: "test_client_id",
            redirectUri: "testapp://auth/callback"
        )

        let pkce = PKCE.generate()
        let url = config.authorizationUrl(pkce: pkce)

        XCTAssertNotNil(url)
        XCTAssertTrue(url!.absoluteString.contains("test_client_id"))
        XCTAssertTrue(url!.absoluteString.contains("testapp://auth/callback"))
        XCTAssertTrue(url!.absoluteString.contains("code_challenge="))
    }

    func testAuthTokensExpiration() {
        let expiredTokens = AuthTokens(
            accessToken: "test",
            idToken: "test",
            refreshToken: "test",
            expiresAt: Date().addingTimeInterval(-60)
        )

        let validTokens = AuthTokens(
            accessToken: "test",
            idToken: "test",
            refreshToken: "test",
            expiresAt: Date().addingTimeInterval(3600)
        )

        XCTAssertTrue(expiredTokens.isExpired)
        XCTAssertFalse(validTokens.isExpired)
    }

    func testAuthTokensExpiresSoon() {
        let soonTokens = AuthTokens(
            accessToken: "test",
            idToken: "test",
            refreshToken: "test",
            expiresAt: Date().addingTimeInterval(30)
        )

        XCTAssertTrue(soonTokens.expiresSoon(within: 60))
        XCTAssertFalse(soonTokens.expiresSoon(within: 10))
    }

    func testPermissions() {
        let permissions: Set<Permission> = [.membersRead, .projectsRead]

        XCTAssertTrue(permissions.contains(.membersRead))
        XCTAssertFalse(permissions.contains(.billingManage))
    }

    func testOrganizationCreation() {
        let org = Organization(
            id: "org_123",
            workosOrgId: "wos_org_456",
            name: "Test Org",
            slug: "test-org"
        )

        XCTAssertEqual(org.id, "org_123")
        XCTAssertEqual(org.name, "Test Org")
    }

    func testOrgSession() {
        let session = OrgSession(
            orgId: "org_123",
            role: "admin",
            permissions: [.membersRead, .projectsCreate]
        )

        XCTAssertEqual(session.orgId, "org_123")
        XCTAssertEqual(session.role, "admin")
        XCTAssertTrue(session.permissions.contains(.membersRead))
    }
}
