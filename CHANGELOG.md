# Changelog

All notable changes to this project will be documented in this file.

## v1.1.0

Feature release. Backward compatible with v1.0.0.

Highlights:
- WorkOS Pipes integration (`PipesClient`, `PipesModels`) — including the GitHub Pipes flow
- Role-based access control client (`RBACClient`) with an `AuthorizationSnapshot`, plus expanded permission model and hooks
- `VaultClient` for WorkOS Vault
- Hardened Keychain handling and richer token models (`SecureKeychain`, `TokenModels`)
- Structured logging via `WorkOSLogger`

## v1.0.0

Initial public release.

Highlights:
- OAuth 2.0 Authorization Code + PKCE via `ASWebAuthenticationSession`
- Token storage in Keychain + refresh support
- Offline session restoration with configurable policy (`.minutes`, `.hours`, `.days`, `.never`)
- Biometric unlock support
- Multi-organization primitives
- Permission hooks + optional admin UI components
- Network connectivity monitoring to enforce online auth invariants
