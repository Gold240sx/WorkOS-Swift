# Changelog

All notable changes to this project will be documented in this file.

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
