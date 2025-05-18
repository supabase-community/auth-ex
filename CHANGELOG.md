# Changelog

All notable changes to this project will be documented in this file.

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
  - `get_server_health/1` to check GoTrue server health status
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