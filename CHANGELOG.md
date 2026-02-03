# Changelog

All notable changes to this project will be documented in this file.

## [0.8.0](https://github.com/supabase-community/auth-ex/compare/v0.7.0...v0.8.0) (2026-02-03)


### Features

* jwt claims ([#72](https://github.com/supabase-community/auth-ex/issues/72)) ([50c2e38](https://github.com/supabase-community/auth-ex/commit/50c2e38019ff28ed1c313651a0daa656f8a1a4e4))
* session helpers, remove broken auto_refresh ([#70](https://github.com/supabase-community/auth-ex/issues/70)) ([4956479](https://github.com/supabase-community/auth-ex/commit/4956479d9d824e91bb51f97aa7f70ed48a209497))


### Bug Fixes

* handle different responses from sign_up baed on user auto-confirm settings ([#68](https://github.com/supabase-community/auth-ex/issues/68)) ([e908280](https://github.com/supabase-community/auth-ex/commit/e908280ce881ef0f90505e4f53617909bdbf589e))
* include user_metadata parsing in user ([#66](https://github.com/supabase-community/auth-ex/issues/66)) ([d7ec55c](https://github.com/supabase-community/auth-ex/commit/d7ec55cff259135ed1023c04a7aa5f936f31b19f))
* optionally use storage_key config for session values namespacing ([#69](https://github.com/supabase-community/auth-ex/issues/69)) ([926939c](https://github.com/supabase-community/auth-ex/commit/926939c9bc11c6337af4f6b4ff214aa9ee78bb1f))


### Miscellaneous Chores

* new liveView mount lifecycle hook for session data ([#74](https://github.com/supabase-community/auth-ex/issues/74)) ([68e0089](https://github.com/supabase-community/auth-ex/commit/68e00898c0c07146b0f69b94fadfeb5640b44862))

## [0.7.0](https://github.com/supabase-community/auth-ex/compare/v0.6.3...v0.7.0) (2026-01-19)


### Features

* **mfa:** mfa interface handling ([#62](https://github.com/supabase-community/auth-ex/issues/62)) ([13245db](https://github.com/supabase-community/auth-ex/commit/13245dba7a7006d0473602cdde0306c9c01b074a))


### Bug Fixes

* correctly build the client key for auto-refresh registry name ([#65](https://github.com/supabase-community/auth-ex/issues/65)) ([8a689f6](https://github.com/supabase-community/auth-ex/commit/8a689f6d4e681fc3d1f296cbb7593af6c8d6147e))
* include options.data in sign up payload ([#63](https://github.com/supabase-community/auth-ex/issues/63)) ([6eea1db](https://github.com/supabase-community/auth-ex/commit/6eea1db438dc3864158aeec28fe741ad8808ae95))

## [0.6.3](https://github.com/supabase-community/auth-ex/compare/v0.6.2...v0.6.3) (2025-12-10)


### Bug Fixes

* follow `json_library` option from main library ([#55](https://github.com/supabase-community/auth-ex/issues/55)) ([6b79f8d](https://github.com/supabase-community/auth-ex/commit/6b79f8d6bb583c3a7064403227076a0741672c02))

## [0.6.2](https://github.com/supabase-community/auth-ex/compare/v0.6.1...v0.6.2) (2025-07-20)

* gen auth task templates ([#51](https://github.com/supabase-community/auth-ex/issues/51)) ([6e86c5f](https://github.com/supabase-community/auth-ex/commit/6e86c5f09784fc99be2891640997e388f37c0fe5))

## [0.6.1](https://github.com/supabase-community/auth-ex/compare/v0.6.0...v0.6.1) (2025-07-20)


### Bug Fixes

* allows compilation when phoenix isn't present and only plug exists ([#46](https://github.com/supabase-community/auth-ex/issues/46)) ([5634705](https://github.com/supabase-community/auth-ex/commit/5634705db7aeb702fd1e130f4e2dafeaa030bad4))

## [0.6.0](https://github.com/supabase-community/auth-ex/compare/v0.5.2...v0.6.0) (2025-07-15)

### Bug Fixes

* cond compile mod/funs that depens on optional dependencies ([#45](https://github.com/supabase-community/auth-ex/issues/45)) ([840279b](https://github.com/supabase-community/auth-ex/commit/840279b2cfd47e5b2e6b5d5c1091c9c993c5c805))

### Code Refactoring

* rename package to supabase_auth ([#43](https://github.com/supabase-community/auth-ex/issues/43)) ([eb220d1](https://github.com/supabase-community/auth-ex/commit/eb220d1c0144ed3c8ee0bb61088282289675114b))

## [0.5.2] - 2025-06-10

### Fixed
- Fixed `sign_in_with_oauth` result format to include flow_type, provider, and URL
- Added anonymous user support with `is_anonymous` field in User schema
- Fixed captcha token handling for anonymous users

## [0.5.1] - 2025-05-20

### Fixed
- Correctly hadnle single strategy on mix task generator

## [0.5.0] - 2025-05-18

### Added
- Implemented auto-refresh token functionality for managing token expiration
- Added reauthentication functionality for sensitive operations
- Enhanced PKCE flow with `exchange_code_for_session` implementation
- Added authentication function generator task for Phoenix applications
- Improved documentation for schema modules including proper typespecs

### Fixed
- Resolved documentation warnings when referenced hidden schema modules
- Fixed compatibility issues with latest Phoenix versions
- Corrected session management in LiveView integration

### Improved
- Streamlined README with better getting started instructions
- Enhanced module documentation for better developer experience
- Improved schema validation and error handling
- Better integration with LSP for enhanced developer tooling
- Updated validation patterns for authentication parameters

## [0.4.1] - 2025-02-17

### Added
- Added new server monitoring functions:
  - `get_server_health/1` to check Auth server health status
  - `get_server_settings/2` to retrieve server configuration
- Implemented `refresh_session/2` for token refresh functionality
- Added `sign_in_anonymously/2` for anonymous authentication
- Added comprehensive unit tests for the public API

### Fixed
- Fixed pagination issues in admin user listing
- Fixed update user functionality in admin API
- Corrected JSON response handling in admin API endpoints
- Resolved authentication path issues when ensuring user authentication

### Improved
- Improved integration with base Supabase SDK
- Enhanced documentation and usage examples
- Better integration between Plug and LiveView components
- Refined error handling for authentication flows
- Improved client module customization options

### Internal
- Updated dependency on supabase_potion to latest version
- Upgraded minimum Elixir version requirement
- Enhanced test coverage across authentication flows
- Refactored code for better maintainability

## [0.4.0] - 2025-01-15

### Added
- Implemented PKCE authentication flow
- Added support for OAuth2 authentication
- Integrated advanced session management
- Added support for custom authentication handlers

### Changed
- Improved error handling mechanisms
- Enhanced LiveView integration
- Updated authentication flow documentation

## [0.3.10] - 2024-12-20

### Added
- Support for custom client modules
- Enhanced plug integration capabilities

### Fixed
- Issue with reusing already started clients
- Authentication path resolution problems

## [0.3.9] - 2024-12-10

### Added
- Resend signup email functionality
- Password reset capabilities

### Fixed
- Access token usage in admin API
- JSON response parsing in admin endpoints

## [0.3.8] - 2024-11-25

### Added
- User update functionality
- Enhanced admin API capabilities

### Fixed
- Authentication path redirection issues
- Session management improvements

## [0.3.7] - 2024-11-10

### Added
- LiveView integration improvements
- Enhanced plug-based authentication

### Changed
- Upgraded minimum Elixir version requirements
- Refined authentication flow handling

## [0.3.6] - 2024-10-25

### Added
- Multiple sign-in method support
- Pagination for user listing

### Fixed
- User update issues in admin API
- Authentication flow edge cases

## [0.3.5] - 2024-10-10

### Added
- SSO authentication support
- Enhanced session management

### Fixed
- Authentication token handling
- Session persistence issues

## [0.3.4] - 2024-09-25

### Added
- OTP authentication support
- Improved error handling

### Changed
- Enhanced documentation
- Refined authentication flows

## [0.3.3] - 2024-09-10

### Added
- Custom authentication handlers
- Enhanced session management

### Fixed
- Authentication flow issues
- Token management improvements

## [0.3.2] - 2024-08-25

### Added
- LiveView authentication hooks
- Enhanced plug integration

### Fixed
- Session management issues
- Authentication path handling

## [0.3.1] - 2024-08-10

### Added
- Basic LiveView support
- Initial plug integration

### Fixed
- Authentication flow issues
- Token handling improvements

## [0.3.0] - 2024-07-25

### Added
- Initial LiveView integration
- Basic plug support
- Core authentication flows
- Session management

### Changed
- Major refactoring of authentication handling
- Improved documentation structure
- Enhanced error handling

## [0.2.1] - 2024-07-10

### Fixed
- Authentication token handling
- Session management issues
- Documentation improvements

## [0.2.0] - 2024-06-25

### Added
- Initial release
- Basic authentication functionality
- User management capabilities
- Session handling
- Basic documentation

### Changed
- Core authentication structure
- Initial API design
- Basic error handling
