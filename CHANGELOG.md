# Changelog

All notable changes to this project will be documented in this file.

## [0.7.0](https://github.com/supabase-community/auth-ex/compare/v0.6.1...v0.7.0) (2025-07-20)


### Features

* add auto-refresh token functionality ([#29](https://github.com/supabase-community/auth-ex/issues/29)) ([a1aa646](https://github.com/supabase-community/auth-ex/commit/a1aa64687972c4f6dd68345c31764251d5e0917f))
* add documentation ([87ec8ea](https://github.com/supabase-community/auth-ex/commit/87ec8ea36ae1841e674fd69ee4ac1a44c57f0e97))
* add identity management functionality ([#26](https://github.com/supabase-community/auth-ex/issues/26)) ([145f0bc](https://github.com/supabase-community/auth-ex/commit/145f0bc29f62f7186da46b888dd5a62a1e37930f))
* add login with SSO ([d84012c](https://github.com/supabase-community/auth-ex/commit/d84012c3256ea7d42e896c01c54d7be10401ced7))
* better integration with sdk and documentation ([d58b1f3](https://github.com/supabase-community/auth-ex/commit/d58b1f3daa15f2e13dc87c7f1c4c0ee054d22849))
* custom client module ([c18930e](https://github.com/supabase-community/auth-ex/commit/c18930e1474c6ad3a58fd87b2a4a5eb7da3f11f3))
* delete mfa facto ([#25](https://github.com/supabase-community/auth-ex/issues/25)) ([875afde](https://github.com/supabase-community/auth-ex/commit/875afde0bb66bc92ec4084b51a237ed425dc8bd8))
* follow base SDK update ([12fab59](https://github.com/supabase-community/auth-ex/commit/12fab59a63c86c7847b55a04fa1c893305d8944b))
* follow supabase_potion release ([#5](https://github.com/supabase-community/auth-ex/issues/5)) ([097d055](https://github.com/supabase-community/auth-ex/commit/097d055cfd779b1ccd5957a01ac9386002af1851))
* get_server_health/1 ([#15](https://github.com/supabase-community/auth-ex/issues/15)) ([2b86a1e](https://github.com/supabase-community/auth-ex/commit/2b86a1e6b89e32621bc266c65250edf3ba777528))
* get_server_settings/2 ([#14](https://github.com/supabase-community/auth-ex/issues/14)) ([e8fcbe8](https://github.com/supabase-community/auth-ex/commit/e8fcbe81d98404f0f45041ec257e9d967fc5acad))
* implement exchange_code_for_session for PKCE flow ([#27](https://github.com/supabase-community/auth-ex/issues/27)) ([a3e4aab](https://github.com/supabase-community/auth-ex/commit/a3e4aab33136092a40aaae408b4ac79abcca21cb))
* implement reauthentication functionality ([#28](https://github.com/supabase-community/auth-ex/issues/28)) ([9691c49](https://github.com/supabase-community/auth-ex/commit/9691c49eead8c57f60453f5f8e32653805b25e9d))
* improve documentation ([#30](https://github.com/supabase-community/auth-ex/issues/30)) ([adb4bdb](https://github.com/supabase-community/auth-ex/commit/adb4bdb99098c6b97e56646e5ef658813f9f8366))
* improved generated documentation ([#32](https://github.com/supabase-community/auth-ex/issues/32)) ([2cb0a3f](https://github.com/supabase-community/auth-ex/commit/2cb0a3f530c44fbda7cb161c460dae21b18bca0e))
* live view and plug integrations ([86c9b36](https://github.com/supabase-community/auth-ex/commit/86c9b3611abd775fea1eb2dbf5e69a7f35831fdd))
* more ways to plug signin and fix pagination issues and fix update user as admin issue ([1769e2a](https://github.com/supabase-community/auth-ex/commit/1769e2a98c766a74bee468e9aa1386aab93c2eda))
* por from supabase-potion ([8525cd4](https://github.com/supabase-community/auth-ex/commit/8525cd402ab7880760eb367139bde70d7526c316))
* refresh_session/2 ([#13](https://github.com/supabase-community/auth-ex/issues/13)) ([da6ba1e](https://github.com/supabase-community/auth-ex/commit/da6ba1e20de9abca2c901d4553e256f21db23d60))
* resend signup email ([3b6b558](https://github.com/supabase-community/auth-ex/commit/3b6b558a6700b95daaad56a1ad99269d66fab408))
* reset password and update user ([163d6b6](https://github.com/supabase-community/auth-ex/commit/163d6b619e7e1e5633a405225352e3b273bf3386))
* sign in with OTP ([1c664e6](https://github.com/supabase-community/auth-ex/commit/1c664e65ad57e83bc8e3c4f960c59c6355a3340f))
* sign_in_anonymously/2 ([#16](https://github.com/supabase-community/auth-ex/issues/16)) ([f4f16dd](https://github.com/supabase-community/auth-ex/commit/f4f16dd01ead3ca735611553e9517b8b8d2b0be6))


### Bug Fixes

* allows compilation when phoenix isn't present and only plug exists ([#46](https://github.com/supabase-community/auth-ex/issues/46)) ([5634705](https://github.com/supabase-community/auth-ex/commit/5634705db7aeb702fd1e130f4e2dafeaa030bad4))
* captcha token for anonymous users ([#35](https://github.com/supabase-community/auth-ex/issues/35)) ([2ca77f6](https://github.com/supabase-community/auth-ex/commit/2ca77f67abea069e9bef5fd003106dce3dbf401c))
* cond compile mod/funs that depens on optional dependencies ([#45](https://github.com/supabase-community/auth-ex/issues/45)) ([840279b](https://github.com/supabase-community/auth-ex/commit/840279b2cfd47e5b2e6b5d5c1091c9c993c5c805))
* coorectly handle single strategy on auth generator ([#33](https://github.com/supabase-community/auth-ex/issues/33)) ([324cf0a](https://github.com/supabase-community/auth-ex/commit/324cf0a8970eb5d8418f8c2c19d81ed6739adc7f))
* correctly fetch/save current user on session on generated templates ([#41](https://github.com/supabase-community/auth-ex/issues/41)) ([c3e89ba](https://github.com/supabase-community/auth-ex/commit/c3e89ba0d14591354ab17c0374f5613c7dbf8ccd))
* do not use access token for admin api ([c0b6c85](https://github.com/supabase-community/auth-ex/commit/c0b6c85cc6336b7a8323f90ddd180dddecb91cac))
* let you reuse already started client ([82d2cfa](https://github.com/supabase-community/auth-ex/commit/82d2cfa4083522663396b2e8842f0ec1069dfe8d))
* logout + request ([#38](https://github.com/supabase-community/auth-ex/issues/38)) ([5774a9c](https://github.com/supabase-community/auth-ex/commit/5774a9c8f9a548675d9ed17747cf851b152a3df0))
* missing skip_http_redirect on query param when linking identity ([#40](https://github.com/supabase-community/auth-ex/issues/40)) ([1f0a97d](https://github.com/supabase-community/auth-ex/commit/1f0a97d7321cd8781ee74efd4bbd1162f04eadfa))
* resolve json on admin api ([4000c33](https://github.com/supabase-community/auth-ex/commit/4000c3341541bb709202d10f74b8b6e10c01d1c4))
* sign_in_with_oauth result ([#36](https://github.com/supabase-community/auth-ex/issues/36)) ([5cde2de](https://github.com/supabase-community/auth-ex/commit/5cde2dea67b9a9ef198deb33b904f933b60cbfcb))
* use not authenticated path when ensure authenticated fails ([d3222b0](https://github.com/supabase-community/auth-ex/commit/d3222b03472625ee0df18a19b1a28bbdc3b391db))


### Miscellaneous Chores

* add badges in the readme ([06c9cdd](https://github.com/supabase-community/auth-ex/commit/06c9cddafa0b52c0ee08fed26464a6cb1dae85ea))
* release 0.6.0 ([#44](https://github.com/supabase-community/auth-ex/issues/44)) ([c169011](https://github.com/supabase-community/auth-ex/commit/c1690119981ea6d454d96462f5932c302fe033e9))
* release 0.6.1 ([#48](https://github.com/supabase-community/auth-ex/issues/48)) ([64052fc](https://github.com/supabase-community/auth-ex/commit/64052fc4d1bcd7a52bb8eb31365ec3cfeb621ac2))


### Code Refactoring

* rename package to supabase_auth ([#43](https://github.com/supabase-community/auth-ex/issues/43)) ([eb220d1](https://github.com/supabase-community/auth-ex/commit/eb220d1c0144ed3c8ee0bb61088282289675114b))

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
