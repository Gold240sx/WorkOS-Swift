//
//  VaultClient.swift
//  WorkOSAuthKitSwift
//
//  Client for WorkOS Vault API key backup/restore. Calls the DevSpace RBAC service
//  (or Vault proxy) which proxies to WorkOS Vault. The app never uses WorkOS secret keys.
//

import Foundation

// MARK: - Models

/// Metadata for a backed-up integration API key.
public struct VaultKeyMetadata: Codable, Sendable {
    public let displayName: String
    public let service: String
    public let configJson: String
    public let createdAt: String
    public let updatedAt: String

    public init(
        displayName: String,
        service: String,
        configJson: String,
        createdAt: String,
        updatedAt: String
    ) {
        self.displayName = displayName
        self.service = service
        self.configJson = configJson
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
        case service
        case configJson = "config_json"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
}

/// Request to create a backed-up key.
public struct VaultCreateKeyRequest: Encodable, Sendable {
    public let name: String
    public let value: String
    public let metadata: VaultKeyMetadata

    public init(name: String, value: String, metadata: VaultKeyMetadata) {
        self.name = name
        self.value = value
        self.metadata = metadata
    }

    enum CodingKeys: String, CodingKey {
        case name
        case value
        case metadata
    }
}

/// Response from creating a key.
public struct VaultCreateKeyResponse: Decodable, Sendable {
    public let id: String
    public let name: String
    public let metadata: VaultKeyMetadataResponse?

    public struct VaultKeyMetadataResponse: Decodable, Sendable {
        public let keyId: String?
        public let updatedAt: String?

        enum CodingKeys: String, CodingKey {
            case keyId = "key_id"
            case updatedAt = "updated_at"
        }
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case metadata
    }
}

/// Response from listing keys (metadata only).
public struct VaultKeyListItem: Decodable, Sendable {
    public let id: String
    public let name: String
    public let metadata: VaultKeyMetadata?
    public let updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case metadata
        case updatedAt = "updated_at"
    }
}

/// Response from listing keys.
public struct VaultListKeysResponse: Decodable, Sendable {
    public let data: [VaultKeyListItem]
}

/// Response from getting a key by name (full value, for restore).
public struct VaultKeyResponse: Decodable, Sendable {
    public let id: String
    public let name: String
    public let value: String
    public let metadata: VaultKeyMetadata?
}

/// Request to update a key value.
public struct VaultUpdateKeyRequest: Encodable, Sendable {
    public let value: String
    public let versionCheck: String?

    public init(value: String, versionCheck: String? = nil) {
        self.value = value
        self.versionCheck = versionCheck
    }

    enum CodingKeys: String, CodingKey {
        case value
        case versionCheck = "version_check"
    }
}

// MARK: - VaultClient

/// Client for WorkOS Vault API key backup/restore via the DevSpace RBAC service.
/// Requires backend to implement /vault/keys endpoints that proxy to WorkOS Vault.
public actor VaultClient {
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

    /// Create a backed-up key.
    public func createKey(
        name: String,
        value: String,
        metadata: VaultKeyMetadata
    ) async throws -> VaultCreateKeyResponse {
        let request = VaultCreateKeyRequest(name: name, value: value, metadata: metadata)
        return try await perform(path: "/vault/keys", method: "POST", body: request)
    }

    /// List backed-up keys (metadata only)
    public func listKeys() async throws -> [VaultKeyListItem] {
        let response: VaultListKeysResponse = try await perform(path: "/vault/keys")
        return response.data
    }

    /// Get a key by name (full value, for restore).
    public func getKeyValue(name: String) async throws -> VaultKeyResponse {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
        return try await perform(path: "/vault/keys/name/\(encoded)")
    }

    /// Update an existing key's value by id.
    public func updateKey(id: String, value: String, versionCheck: String? = nil) async throws {
        let request = VaultUpdateKeyRequest(value: value, versionCheck: versionCheck)
        let _: EmptyResponse = try await perform(
            path: "/vault/keys/\(id)",
            method: "PUT",
            body: request
        )
    }

    /// Update an existing key's value by name (convenience for integration keys).
    public func updateKeyByName(name: String, value: String, versionCheck: String? = nil) async throws {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
        let request = VaultUpdateKeyRequest(value: value, versionCheck: versionCheck)
        let _: EmptyResponse = try await perform(
            path: "/vault/keys/name/\(encoded)",
            method: "PUT",
            body: request
        )
    }

    /// Delete a backed-up key by id.
    public func deleteKey(id: String) async throws {
        let _: EmptyResponse = try await perform(
            path: "/vault/keys/\(id)",
            method: "DELETE"
        )
    }

    /// Delete a backed-up key by name (convenience for integration keys).
    public func deleteKeyByName(name: String) async throws {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
        let _: EmptyResponse = try await perform(
            path: "/vault/keys/name/\(encoded)",
            method: "DELETE"
        )
    }

    private func perform<Response: Decodable>(
        path: String,
        method: String = "GET",
        queryItems: [URLQueryItem] = [],
        body: (any Encodable)? = nil
    ) async throws -> Response {
        guard let url = configuration.rbacServiceURL(path: path, queryItems: queryItems) else {
            throw AuthError.configurationError("Vault service URL not configured (RBAC backend URL required)")
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
