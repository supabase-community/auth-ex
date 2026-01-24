defmodule Supabase.Auth do
  @moduledoc """
  The main interface for interacting with Supabase's Auth authentication service.
  This module provides comprehensive functionality for user authentication, session management,
  and identity handling in Elixir applications.

  ## Features

  * Multiple authentication methods: password, OAuth, OTP, SSO, and anonymous
  * Session management: creation, refresh, and validation
  * User management: registration, profile updates, and password recovery
  * Multi-factor authentication support
  * Identity linking/unlinking for social providers
  * Server health and settings information

  ## Integration Options

  * **HTTP API client**: Core functions for direct API interaction
  * **Plug integration**: For traditional web applications (`Supabase.Auth.Plug`)
  * **Phoenix LiveView**: For real-time applications (`Supabase.Auth.LiveView`)

  ## Example Usage

  Basic authentication with email and password:

      {:ok, session} = Supabase.Auth.sign_in_with_password(client, %{
        email: "user@example.com",
        password: "secure-password"
      })

  Retrieve the current user:

      {:ok, user} = Supabase.Auth.get_user(client, session)

  See individual function documentation for more examples and options.

  For comprehensive information about the Auth API, check the official documentation at:
  https://supabase.com/docs/reference/javascript/auth-api
  """

  @behaviour Supabase.Auth.Behaviour

  alias Supabase.Auth.Schemas.ResendParams
  alias Supabase.Auth.Schemas.ServerHealth
  alias Supabase.Auth.Schemas.ServerSettings
  alias Supabase.Auth.Schemas.SignInAnonymously
  alias Supabase.Auth.Schemas.SignInWithIdToken
  alias Supabase.Auth.Schemas.SignInWithOauth
  alias Supabase.Auth.Schemas.SignInWithOTP
  alias Supabase.Auth.Schemas.SignInWithPassword
  alias Supabase.Auth.Schemas.SignInWithSSO
  alias Supabase.Auth.Schemas.SignUpWithPassword
  alias Supabase.Auth.Schemas.UserParams
  alias Supabase.Auth.Session
  alias Supabase.Auth.User
  alias Supabase.Auth.UserHandler
  alias Supabase.Client

  @doc """
  Retrieves the currently authenticated user's profile.

  This function makes an API request to get the most up-to-date user information
  associated with the provided session. This is useful for checking the current
  state of the user including verification status, metadata, and linked identities.

  ## Parameters

  * `client` - The Supabase client to use for the request
  * `session` - An active session containing a valid access token

  ## Returns

  * `{:ok, user}` - Successfully retrieved user profile
  * `{:error, error}` - Failed to retrieve user profile

  ## Examples

      iex> session = %Supabase.Auth.Session{access_token: "eyJhbG..."}
      iex> {:ok, user} = Supabase.Auth.get_user(client, session)
      iex> user.email
      "user@example.com"

      # If the session is invalid or expired
      iex> {:error, %Supabase.Error{code: :unauthorized}} = Supabase.Auth.get_user(client, invalid_session)
  """
  @impl true
  def get_user(%Client{} = client, %Session{} = session) do
    with {:ok, response} <- UserHandler.get_user(client, session.access_token) do
      User.parse(response.body)
    end
  end

  @doc """
  Signs in a user with ID token.

  This method allows authentication using ID tokens issued by supported external providers like Google, Apple, Azure, etc.
  The provider's ID token is verified and used to create or authenticate a user in the Supabase system.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in:
      * `provider` - Provider name identifying which provider should be used to verify the provided token (e.g., 'google', 'apple', 'azure', 'facebook', 'kakao')
      * `token` - OIDC ID token issued by the specified provider
      * `access_token` - Optional if the ID token contains an `at_hash` claim
      * `nonce` - Optional if the ID token contains a `nonce` claim
      * `options` - Optional parameters:
        * `captcha_token` - Verification token from CAPTCHA challenge

  ## Returns
    - `{:ok, session}` - Successfully authenticated with ID token, returns a valid session
    - `{:error, error}` - Authentication failed

  ## Examples
      iex> credentials = %{
      ...>   provider: "google",
      ...>   token: "eyJhbGciO..." # ID token from Google
      ...> }
      iex> Supabase.Auth.sign_in_with_id_token(client, credentials)
      {:ok, %Supabase.Auth.Session{}}
  """
  @impl true
  def sign_in_with_id_token(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithIdToken.parse(credentials),
         {:ok, resp} <- UserHandler.sign_in_with_id_token(client, credentials) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Signs in a user with OAuth.

  This method initiates authentication with an OAuth provider (like GitHub, Google, etc.)
  and returns a URL to redirect the user to complete the authentication process.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in:
      * `provider` - One of the supported OAuth providers (e.g., 'apple', 'azure', 'bitbucket', 'discord', 'email', 'facebook', 'figma', 'github', 'gitlab', 'google', 'kakao', 'keycloak', 'linkedin', 'notion', 'phone', 'slack', 'spotify', 'twitch', 'twitter', 'workos', 'zoom', 'fly')
      * `options` - Optional parameters:
        * `redirect_to` - URL to redirect the user after successful authentication
        * `scopes` - List of OAuth scopes to request
        * `query_params` - Additional query parameters to include in the OAuth URL
        * `skip_browser_redirect` - Whether to skip redirecting the browser to the authorization URL

  ## Returns
    - `{:ok, data}` - Successfully generated OAuth URL; `data` contains the url for the redirection, the provider and the flow type. In case of a `PKCE` flow, it also contains the `code_verifier`, `code_challenge` and `code_challenge_method`.
    - `{:error, error}` - Failed to generate OAuth URL

  ## Examples
      iex> credentials = %{
      ...>   provider: :github,
      ...>   options: %{
      ...>     redirect_to: "https://example.com/callback"
      ...>   }
      ...> }
      iex> Supabase.Auth.sign_in_with_oauth(client, credentials)
      {:ok, %{provider: :github, url: "https://auth.supabase.com/authorize?provider=github&...", flow_type: :implicit}}
  """
  @impl true
  def sign_in_with_oauth(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithOauth.parse(credentials) do
      data = UserHandler.get_data_for_provider(client, credentials)
      {:ok, data}
    end
  end

  @doc """
  Signs in a user with OTP (One-Time Password).

  This method sends a one-time password to the user's email or phone number for authentication.
  The user will need to verify this code to complete the authentication process using the
  `verify_otp/2` function.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in:
      * `email` - User's email address (required if phone not provided)
      * `phone` - User's phone number (required if email not provided)
      * `options` - Optional parameters:
        * `data` - Additional data to include with the sign in request
        * `email_redirect_to` - URL to redirect user after email verification
        * `captcha_token` - Verification token from CAPTCHA challenge
        * `channel` - Delivery channel for phone OTPs (defaults to "sms")
        * `should_create_user` - Whether to create a new user if one doesn't exist (defaults to true)

  ## Returns
    - `:ok` - Successfully sent OTP via email
    - `{:ok, message_id}` - Successfully sent OTP via SMS, returns message ID
    - `{:error, error}` - Failed to send OTP

  ## Examples
      iex> credentials = %{email: "user@example.com"}
      iex> Supabase.Auth.sign_in_with_otp(client, credentials)
      :ok

      iex> credentials = %{phone: "+15555550123", options: %{channel: "sms"}}
      iex> Supabase.Auth.sign_in_with_otp(client, credentials)
      {:ok, "message-id-123"}
  """
  @impl true
  def sign_in_with_otp(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithOTP.parse(credentials) do
      UserHandler.sign_in_with_otp(client, credentials)
    end
  end

  @doc """
  Verifies an OTP (One-Time Password) code.

  This function completes the authentication process started with `sign_in_with_otp/2`
  by verifying the OTP code that was sent to the user's email or phone.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `params` - The parameters to use for the verification. Use one of the following formats:

      For email verification:
      * `email` - The email address that received the OTP
      * `token` - The OTP code that was sent
      * `type` - The verification type (`:signup`, `:invite`, `:magiclink`, `:recovery`, `:email_change`)
      * `options` - Optional parameters:
        * `redirect_to` - URL to redirect to after verification
        * `captcha_token` - Verification token from CAPTCHA challenge

      For phone verification:
      * `phone` - The phone number that received the OTP
      * `token` - The OTP code that was sent
      * `type` - The verification type (`:sms`, `:phone_change`)
      * `options` - Optional parameters:
        * `redirect_to` - URL to redirect to after verification
        * `captcha_token` - Verification token from CAPTCHA challenge

      For token hash verification:
      * `token_hash` - The token hash to verify
      * `type` - The verification type (same as email verification types)
      * `options` - Optional parameters (same as above)

  ## Returns
    - `{:ok, session}` - Successfully verified OTP, returns a session with tokens
    - `{:error, error}` - Failed to verify OTP

  ## Examples
      iex> params = %{email: "user@example.com", token: "123456", type: :signup}
      iex> Supabase.Auth.verify_otp(client, params)
      {:ok, %Supabase.Auth.Session{}}

      iex> params = %{phone: "+15555550123", token: "123456", type: :sms}
      iex> Supabase.Auth.verify_otp(client, params)
      {:ok, %Supabase.Auth.Session{}}
  """
  @impl true
  def verify_otp(%Client{} = client, params) do
    with {:ok, response} <- UserHandler.verify_otp(client, params) do
      Session.parse(response.body)
    end
  end

  @doc """
  Signs in a user with SSO (Single Sign-On).

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in:
      * `provider_id` - The ID of the SSO provider (required if domain not provided)
      * `domain` - The domain of the SSO provider (required if provider_id not provided)
      * `options` - Optional parameters:
        * `redirect_to` - URL to redirect the user after successful authentication
        * `captcha_token` - Verification token from CAPTCHA challenge

  ## Examples
      iex> credentials = %{domain: "example.org", options: %{redirect_to: "https://example.com/callback"}}
      iex> Supabase.Auth.sign_in_with_sso(client, credentials)
      {:ok, "https://auth.supabase.com/sso/..."}

      # Or using provider_id
      iex> credentials = %{provider_id: "sso-provider-id", options: %{redirect_to: "https://example.com/callback"}}
      iex> Supabase.Auth.sign_in_with_sso(client, credentials)
      {:ok, "https://auth.supabase.com/sso/..."}
  """
  @impl true
  def sign_in_with_sso(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithSSO.parse(credentials) do
      UserHandler.sign_in_with_sso(client, credentials)
    end
  end

  @doc """
  Authenticates a user with email/phone and password.

  This is the most common authentication method used for traditional credential-based
  authentication. Upon successful authentication, a session is created containing
  access and refresh tokens.

  ## Parameters

  * `client` - The Supabase client to use for the request
  * `credentials` - Map with authentication details:
    * `email` - User's email address (required if phone not provided)
    * `phone` - User's phone number (required if email not provided)
    * `password` - User's password (required)
    * `options` - Optional parameters:
      * `captcha_token` - Verification token from CAPTCHA challenge
      * `data` - Additional data to include with the sign in request

  ## Returns

  * `{:ok, session}` - Successfully authenticated, returns session with tokens
  * `{:error, error}` - Authentication failed

  ## Examples

      # Sign in with email
      iex> credentials = %{email: "user@example.com", password: "secure-password"}
      iex> {:ok, session} = Supabase.Auth.sign_in_with_password(client, credentials)
      iex> session.access_token
      "eyJhbG..."

      # Sign in with phone
      iex> credentials = %{phone: "+15555550123", password: "secure-password"}
      iex> {:ok, session} = Supabase.Auth.sign_in_with_password(client, credentials)

      # Sign in with additional options
      iex> credentials = %{
      ...>   email: "user@example.com",
      ...>   password: "secure-password",
      ...>   options: %{captcha_token: "verify-token-123"}
      ...> }
      iex> {:ok, session} = Supabase.Auth.sign_in_with_password(client, credentials)

  ## Related

  * `sign_up/2` - Create a new user account with email/password
  * `reset_password_for_email/3` - Reset a forgotten password
  """
  @impl true
  def sign_in_with_password(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithPassword.parse(Map.new(credentials)),
         {:ok, response} <- UserHandler.sign_in_with_password(client, credentials) do
      Session.parse(response.body)
    end
  end

  @doc """
  Signs in a user anonymously.

  This method creates a new anonymous user in the Supabase auth system.
  Anonymous users can later be converted to permanent users by linking
  identities or adding credentials.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `opts` - Optional parameters for anonymous sign-in:
      * `data` - Additional data to include with the sign-in request
      * `captcha_token` - Verification token from CAPTCHA challenge

  ## Returns
    - `{:ok, session}` - Successfully signed in anonymously, returns a session with tokens
    - `{:error, error}` - Failed to sign in anonymously

  ## Examples
      iex> Supabase.Auth.sign_in_anonymously(client)
      {:ok, %Supabase.Auth.Session{}}

      iex> Supabase.Auth.sign_in_anonymously(client, %{data: %{user_metadata: %{locale: "en-US"}}})
      {:ok, %Supabase.Auth.Session{}}
  """
  @impl true
  def sign_in_anonymously(%Client{} = client, opts \\ %{}) do
    with {:ok, params} <- SignInAnonymously.parse(Map.new(opts)),
         {:ok, resp} <- UserHandler.sign_in_anonymously(client, params) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Signs up a user with email/phone and password.

  ⚠️ The return value depends on the Supabase Auth configuration (email confirmation, auto-confirm, and PKCE).

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign up:
      * `email` - User's email address (required if phone not provided)
      * `phone` - User's phone number (required if email not provided)
      * `password` - User's password (required)
      * `options` - Optional parameters:
        * `email_redirect_to` - URL to redirect the user after email confirmation
        * `data` - Additional data to include with the sign up
        * `captcha_token` - Verification token from CAPTCHA challenge

  ## Return values

  - `{:ok, %Supabase.Auth.User{}}`
    Returned when email confirmation is required and no session is issued.

  - `{:ok, %Supabase.Auth.Session{}}`
    Returned when auto-confirm is enabled.

  - `{:ok, %Supabase.Auth.Session{}, challenge}`
    Returned when PKCE flow is enabled.

  - `{:error, changeset | error}`
    Returned on validation or API failure.

  ## Examples

      iex> credentials = %{email: "user@example.com", password: "secure-password"}
      iex> {:ok, result} = Supabase.Auth.sign_up(client, credentials)
      iex> case result do
      ...>   %Supabase.Auth.Session{} ->
      ...>     "user logged in"
      ...>
      ...>   %Supabase.Auth.User{} ->
      ...>     "user needs confirmation"
      ...> end
      "user logged in"
  """
  @impl true
  def sign_up(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignUpWithPassword.parse(credentials) do
      UserHandler.sign_up(client, credentials)
    end
  end

  @doc """
  Sends a recovery password email for the given email address.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `email` - A valid user email address to recover password
    - `opts`:
      - `redirect_to`: the url where the user should be redirected to reset their password
      - `captcha_token`

  ## Examples
    iex> Supabase.Auth.reset_password_for_email(client, "john@example.com", redirect_to: "http://localohst:4000/reset-pass")
    :ok
  """
  @impl true
  def reset_password_for_email(%Client{} = client, email, opts) do
    UserHandler.recover_password(client, email, Map.new(opts))
  end

  @doc """
  Resends a signup confirm email for the given email address.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `email` - A valid user email address to recover password
    - `opts` - Options for the resend operation:
      * `type` - The type of OTP to resend (`:sms`, `:signup`, `:phone_change`, `:email_change`)
      * `options` - Additional options:
        * `email_redirect_to` - The URL where the user should be redirected after confirming their email
        * `captcha_token` - Token from a CAPTCHA verification if enabled

  ## Returns
    - `:ok` - Successfully initiated resend operation
    - `{:error, error}` - Failed to resend confirmation

  ## Examples
    iex> Supabase.Auth.resend(client, "john@example.com", %{type: :signup, options: %{email_redirect_to: "http://localhost:4000/reset-pass"}})
    :ok
  """
  @impl true
  def resend(%Client{} = client, email, opts) do
    with {:ok, params} <- ResendParams.parse(Map.new(opts)) do
      UserHandler.resend(client, email, params)
    end
  end

  if Code.ensure_loaded?(Plug) or Code.ensure_loaded?(Phoenix.LiveView.Socket) do
    @doc """
    Updates the current logged in user.

    This function allows updating various user attributes including email, phone,
    password, and user metadata. The user must be authenticated.

    ## Parameters
      - `client` - The `Supabase` client to use for the request.
      - `conn` - The current `Plug.Conn` or `Phoenix.LiveView.Socket` to get current user
      - `attrs` - Attributes to update:
        * `email` - New email address for the user
        * `phone` - New phone number for the user
        * `password` - New password for the user
        * `data` - Additional user metadata to update
        * `nonce` - Optional nonce for email change verification
        * `email_redirect_to` - URL to redirect after email change confirmation

    ## Returns
      - `{:ok, conn}` - User was successfully updated, returns updated conn with session
      - `{:error, reason}` - Failed to update user

    ## Examples
        iex> params = %{email: "another@example.com", password: "new-pass"}
        iex> Supabase.Auth.update_user(client, conn, params)
        {:ok, conn}

        iex> params = %{data: %{name: "John Doe", avatar_url: "https://example.com/avatar.png"}}
        iex> Supabase.Auth.update_user(client, conn, params)
        {:ok, conn}
    """
    @impl true
    def update_user(%Client{} = client, conn, attrs) do
      with {:ok, params} <- UserParams.parse(attrs) do
        if conn.assigns.current_user do
          UserHandler.update_user(client, conn, params)
        else
          {:error, :no_user_logged_in}
        end
      end
    end
  end

  @doc """
  Exchanges a refresh token for a new session.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `refresh_token` - The refresh token to use for the request.

  ## Examples
      iex> Supabase.Auth.refresh_session(client, "refresh_token")
      {:ok, %Supabase.Auth.Session{}}
  """
  @impl true
  def refresh_session(%Client{} = client, refresh_token) do
    with {:ok, resp} <- UserHandler.refresh_session(client, refresh_token) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Retrieves the server health from the Auth API.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.

  ## Examples
      iex> Supabase.Auth.get_server_health(client)
      {:ok, %Supabase.Auth.ServerHealth{}}
  """
  @impl true
  def get_server_health(%Client{} = client) do
    with {:ok, resp} <- UserHandler.get_server_health(client) do
      ServerHealth.parse(resp.body)
    end
  end

  @doc """
  Retrieves the server settings from the Auth API.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.

  ## Examples
      iex> Supabase.Auth.get_server_settings(client)
      {:ok, %Supabase.Auth.ServerSettings{}}
  """
  @impl true
  def get_server_settings(%Client{} = client) do
    with {:ok, resp} <- UserHandler.get_server_settings(client) do
      ServerSettings.parse(resp.body)
    end
  end

  @doc """
  Retrieves the auth module handle from the application configuration.
  Check https://hexdocs.pm/supabase_auth/readme.html#usage
  """
  def get_auth_module! do
    Application.get_env(:supabase_auth, :auth_module) ||
      raise(Supabase.Auth.MissingConfig, key: :auth_module)
  end

  @doc """
  Gets a URL to link a new identity to the authenticated user's account.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request.
    - `credentials` - The OAuth credentials to use for identity linking:
       * `provider` - One of the supported OAuth providers (e.g., 'apple', 'azure', 'github', 'google', etc.)
       * `options` - Optional parameters:
         * `redirect_to` - URL to redirect the user after successful authentication
         * `scopes` - List of OAuth scopes to request
         * `query_params` - Additional query parameters to include in the OAuth URL
         * `skip_browser_redirect` - Whether to skip redirecting the browser to the authorization URL

  ## Returns
    - `{:ok, result}` - Successfully generated an identity linking URL, where result is a map containing:
       * `provider` - The provider specified in the request
       * `url` - The authorization URL to redirect to
    - `{:error, error}` - Failed to generate an identity linking URL

  ## Examples
      iex> session = %Supabase.Auth.Session{access_token: "example_token"}
      iex> credentials = %{provider: :github}
      iex> Supabase.Auth.link_identity(client, session, credentials)
      {:ok, %{provider: :github, url: "https://..."}}
  """
  @impl true
  def link_identity(%Client{} = client, %Session{} = session, credentials) do
    with {:ok, credentials} <- SignInWithOauth.parse(credentials) do
      UserHandler.link_identity(client, session.access_token, credentials)
    end
  end

  @doc """
  Unlinks an identity from the authenticated user's account.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request.
    - `identity_id` - The ID of the identity to unlink.

  ## Examples
      iex> session = %Supabase.Auth.Session{access_token: "example_token"}
      iex> identity_id = "1234567890"
      iex> Supabase.Auth.unlink_identity(client, session, identity_id)
      :ok
  """
  @impl true
  def unlink_identity(%Client{} = client, %Session{} = session, identity_id) do
    UserHandler.unlink_identity(client, session.access_token, identity_id)
  end

  @doc """
  Gets all identities for the authenticated user.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request.

  ## Examples
      iex> session = %Supabase.Auth.Session{access_token: "example_token"}
      iex> Supabase.Auth.get_user_identities(client, session)
      {:ok, [%Supabase.Auth.User.Identity{}, ...]}
  """
  @impl true
  def get_user_identities(%Client{} = client, %Session{} = session) do
    with {:ok, response} <- UserHandler.get_user_identities(client, session.access_token) do
      User.Identity.parse_list(response.body)
    end
  end

  @doc """
  Exchanges an authorization code for a session.

  Used in the PKCE (Proof Key for Code Exchange) flow to convert an authorization code
  into a valid session using a code_verifier that matches the previously sent code_challenge.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `auth_code` - The authorization code received from the OAuth provider.
    * `code_verifier` - The original code verifier that was used to generate the code challenge.
    * `opts` - Additional options:
      * `redirect_to` - The URL to redirect to after successful authentication.

  ## Examples
      iex> auth_code = "received_auth_code"
      iex> code_verifier = "original_code_verifier"
      iex> Supabase.Auth.exchange_code_for_session(client, auth_code, code_verifier)
      {:ok, %Supabase.Auth.Session{}}
  """
  @impl true
  def exchange_code_for_session(%Client{} = client, auth_code, code_verifier, opts \\ %{}) do
    with {:ok, resp} <- UserHandler.exchange_code_for_session(client, auth_code, code_verifier, opts) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Sends a reauthentication request for the authenticated user.

  This method is typically used when performing sensitive operations that require
  recent authentication. It sends a one-time password (OTP) to the user's email
  or phone number, which they need to verify to confirm their identity.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `session` - The current user session containing the access token.

  ## Examples
      iex> session = %Supabase.Auth.Session{access_token: "example_token"}
      iex> Supabase.Auth.reauthenticate(client, session)
      :ok
  """
  @impl true
  def reauthenticate(%Client{} = client, %Session{} = session) do
    UserHandler.reauthenticate(client, session.access_token)
  end

  @typedoc """
  An authentication method reference (AMR) entry.

  An entry designates what method was used by the user to verify their
  identity and at what time.

  Note: Custom access token hooks can return AMR claims as either:
  - An array of AMREntry objects (detailed format with timestamps)
  - An array of strings (RFC-8176 compliant format)

  Timestamp when the method was successfully used. Represents number of
  seconds since 1st January 1970 (UNIX epoch) in UTC.
  """
  @type amr_entry :: %{
          timestamp: number,
          method:
            :password
            | :otp
            | :oauth
            | :totp
            | :"mfa/totp"
            | :"mfa/phone"
            | :"mfa/webauthn"
            | :anonymous
            | :"sso/saml"
            | :magiclink
            | :web3
            | :"oauth_provider/authorization_code"
        }

  @type user_metadata :: %{provider: String.t() | nil, providers: list(String.t()) | nil} | %{String.t() => term}

  @typedoc """
  JWT Payload containing claims for Supabase authentication tokens.

  Required claims (iss, aud, exp, iat, sub, role, aal, session_id) are inherited from RequiredClaims.
  All other claims are optional as they can be customized via Custom Access Token Hooks.

  Authentication Method References.
   Supports both RFC-8176 compliant format (string[]) and detailed format (AMREntry[]).
   - String format: ['password', 'otp'] - RFC-8176 compliant
   - Object format: [{ method: 'password', timestamp: 1234567890 }] - includes timestamps

  Check https://supabase.com/docs/guides/auth/jwt-fields
  """
  @type jwt_payload ::
          %{String.t() => term}
          | %{
              email: String.t() | nil,
              phone: String.t() | nil,
              is_anonymous: boolean | nil,
              jti: String.t() | nil,
              nbf: number | nil,
              app_metadata: user_metadata | nil,
              user_metadata: user_metadata | nil,
              ref: String.t() | nil,
              amr: list(amr_entry) | list(String.t())
            }

  @type jwt_header :: %{
          alg: :RS256 | :ES256 | :HS256,
          kid: String.t(),
          typ: String.t()
        }

  @doc """
  Extracts the JWT claims present in the access token by first verifying the
  JWT against the server's JSON Web Key Set endpoint
  `/.well-known/jwks.json` which is often cached, resulting in significantly
  faster responses.

  If the project is not using an asymmetric JWT signing key (like ECC or
  RSA) it always sends a request to the Auth server to verify the JWT.

  ## Parameters
    * `client` - The Supabase client to use for the request
    * `jwt` - The JWT you wish to verify (required)
    * `opts` - Various additional options that allow you to customize the behavior of this method.
      * `allow_expired` - If set to `true` the `exp` claim will not be validated against the current time.
      * `jwks` - If set, this JSON Web Key Set is going to have precedence over the cached value available on the server.

  ## Returns
    * `{:ok, result}` - Successfully verified and decoded JWT, where result contains:
      * `claims` - The JWT payload with user claims
      * `header` - The JWT header with algorithm and key ID
      * `signature` - The JWT signature as binary
    * `{:error, error}` - Failed to verify or decode JWT

  ## Examples

      # Verify the access token from a session
      iex> session = %Supabase.Auth.Session{access_token: "eyJhbG..."}
      iex> {:ok, result} = Supabase.Auth.get_claims(client, session.access_token)
      iex> result.claims.sub
      "user-id-123"

      # Allow expired tokens
      iex> {:ok, result} = Supabase.Auth.get_claims(client, expired_token, allow_expired: true)

      # Provide custom JWKS
      iex> jwks = %{keys: [%{kty: :rsa, kid: "key-1", ...}]}
      iex> {:ok, result} = Supabase.Auth.get_claims(client, token, jwks: jwks)
  """
  @spec get_claims(Client.t(), String.t(), keyword(opt)) ::
          {:ok, %{claims: jwt_payload, header: jwt_header, signature: binary()}} | {:error, term()}
        when opt: {:allow_expired, boolean()} | {:jwks, %{keys: list(jwk)} | nil},
             jwk: %{kty: :rsa | :ec | :oct, key_ops: list(String.t()), alg: String.t() | nil, kid: String.t() | nil}
  def get_claims(%Client{} = client, jwt, opts \\ []) when is_binary(jwt) do
    with {:ok, {header, payload, signature}} <- decode_jwt_parts(jwt),
         :ok <- maybe_validate_expiry(payload, opts) do
      verify_jwt(client, jwt, header, payload, signature, opts)
    end
  end

  # Decodes JWT into its three parts without verification
  defp decode_jwt_parts(token) do
    with %JOSE.JWT{fields: payload} <- JOSE.JWT.peek(token),
         header_json when is_binary(header_json) <- JOSE.JWS.peek_protected(token),
         {:ok, header} <- Supabase.decode_json(header_json),
         [_header, _payload, signature_b64] <- String.split(token, "."),
         {:ok, signature} <- Base.url_decode64(signature_b64, padding: false) do
      header_map = %{
        alg: String.to_atom(header["alg"]),
        kid: header["kid"],
        typ: header["typ"] || "JWT"
      }

      {:ok, {header_map, payload, signature}}
    else
      _ -> {:error, :invalid_jwt_format}
    end
  end

  defp maybe_validate_expiry(payload, opts) do
    allow_expired = Keyword.get(opts, :allow_expired, false)

    if allow_expired, do: :ok, else: validate_jwt_expiry(payload)
  end

  defp validate_jwt_expiry(%{"exp" => exp}) when is_number(exp) do
    if System.os_time(:second) >= exp do
      {:error, :jwt_expired}
    else
      :ok
    end
  end

  defp validate_jwt_expiry(_), do: :ok

  defp verify_jwt(client, token, header, payload, signature, opts) do
    if symmetric_or_missing_kid?(header) do
      verify_with_server(client, token, header, payload, signature)
    else
      verify_with_jwks(client, token, header, payload, signature, opts)
    end
  end

  defp symmetric_or_missing_kid?(%{alg: alg, kid: kid}) do
    alg_str = Atom.to_string(alg)
    String.starts_with?(alg_str, "HS") or is_nil(kid)
  end

  defp symmetric_or_missing_kid?(%{alg: alg}) do
    alg_str = Atom.to_string(alg)
    String.starts_with?(alg_str, "HS")
  end

  # Fallback to server verification via get_user
  defp verify_with_server(client, token, header, payload, signature) do
    case UserHandler.get_user(client, token) do
      {:ok, _response} ->
        {:ok, %{claims: payload, header: header, signature: signature}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp verify_with_jwks(client, token, header, payload, signature, opts) do
    with {:ok, jwks} <- get_jwks(client, opts),
         {:ok, jwk} <- find_jwk_by_kid(jwks, header.kid),
         {:ok, _} <- verify_jwt_signature(token, jwk) do
      {:ok, %{claims: payload, header: header, signature: signature}}
    else
      {:error, _reason} ->
        verify_with_server(client, token, header, payload, signature)
    end
  end

  defp get_jwks(client, opts) do
    case Keyword.get(opts, :jwks) do
      nil -> fetch_jwks_from_server(client)
      %{"keys" => keys} -> {:ok, keys}
      %{keys: keys} -> {:ok, keys}
    end
  end

  defp fetch_jwks_from_server(%Client{} = client) do
    alias Supabase.Auth.Request, as: AuthRequest
    alias Supabase.Fetcher
    alias Supabase.Fetcher.Request
    alias Supabase.Fetcher.Response

    case client
         |> AuthRequest.base("/.well-known/jwks.json")
         |> Request.with_method(:get)
         |> Fetcher.request() do
      {:ok, %Response{body: %{"keys" => keys}}} when is_list(keys) ->
        {:ok, keys}

      {:ok, _} ->
        {:error, :invalid_jwks_response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp find_jwk_by_kid(keys, kid) do
    case Enum.find(keys, &(&1["kid"] == kid)) do
      nil -> {:error, :jwk_not_found}
      jwk -> {:ok, jwk}
    end
  end

  defp verify_jwt_signature(token, jwk) do
    jose_jwk = JOSE.JWK.from_map(jwk)

    case JOSE.JWT.verify(jose_jwk, token) do
      {true, _jwt, _jws} -> {:ok, :verified}
      {false, _, _} -> {:error, :invalid_jwt_signature}
    end
  end

  ## Elixir specific helpers

  ## Elixir specific helpers

  @doc """
  Refreshes session only if it's expiring soon or expired.

  This is useful for proactive token refresh in request handlers.
  Returns the original session if refresh is not needed.

  ## Options

    * `:within` - Seconds before expiry to trigger refresh (default: 300)
    * `:force` - Force refresh even if not expiring (default: false)

  ## Examples

      # Only refresh if expiring within 5 minutes
      case refresh_if_needed(client, session) do
        {:ok, new_session} -> # Use new session (may be same as input)
        {:error, reason} -> # Handle error
      end

      # Custom margin
      refresh_if_needed(client, session, within: 60)

      # Force refresh regardless of expiry
      refresh_if_needed(client, session, force: true)
  """
  @spec refresh_if_needed(Client.t(), Session.t(), keyword()) ::
          {:ok, Session.t()} | {:error, term()}
  def refresh_if_needed(%Client{} = client, %Session{} = session, opts \\ []) do
    force = Keyword.get(opts, :force, false)

    if Session.needs_refresh?(session, opts) or force do
      refresh_session(client, session.refresh_token)
    else
      {:ok, session}
    end
  end

  @doc """
  Validates session and refreshes if needed, in one operation.

  This is the recommended way to ensure you have a valid session
  in your request handlers.

  ## Options

    * `:within` - Seconds before expiry to trigger refresh (default: 300)

  ## Examples

      case ensure_valid_session(client, session) do
        {:ok, valid_session} ->
          # Guaranteed to have valid, non-expiring session
          make_api_call(valid_session)

        {:error, :invalid_session} ->
          # Session is malformed
          redirect_to_login()

        {:error, :refresh_failed} ->
          # Couldn't refresh expired session
          redirect_to_login()
      end
  """
  @spec ensure_valid_session(Client.t(), Session.t(), keyword()) ::
          {:ok, Session.t()} | {:error, :invalid_session | :refresh_failed}
  def ensure_valid_session(%Client{} = client, %Session{} = session, opts \\ []) do
    cond do
      not Session.valid?(session) ->
        {:error, :invalid_session}

      Session.needs_refresh?(session, opts) ->
        with {:error, _} <- refresh_session(client, session.refresh_token), do: {:error, :refresh_failed}

      true ->
        {:ok, session}
    end
  end
end
