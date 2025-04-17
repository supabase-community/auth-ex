defmodule Supabase.GoTrue do
  @moduledoc """
  The main interface for interacting with Supabase's GoTrue authentication service.
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
  * **Plug integration**: For traditional web applications (`Supabase.GoTrue.Plug`)
  * **Phoenix LiveView**: For real-time applications (`Supabase.GoTrue.LiveView`)

  ## Example Usage

  Basic authentication with email and password:

      {:ok, session} = Supabase.GoTrue.sign_in_with_password(client, %{
        email: "user@example.com",
        password: "secure-password"
      })

  Retrieve the current user:

      {:ok, user} = Supabase.GoTrue.get_user(client, session)

  See individual function documentation for more examples and options.

  For comprehensive information about the GoTrue API, check the official documentation at:
  https://supabase.com/docs/reference/javascript/auth-api
  """

  @behaviour Supabase.GoTrueBehaviour

  alias Supabase.Client
  alias Supabase.GoTrue.Schemas.ResendParams
  alias Supabase.GoTrue.Schemas.ServerHealth
  alias Supabase.GoTrue.Schemas.ServerSettings
  alias Supabase.GoTrue.Schemas.SignInAnonymously
  alias Supabase.GoTrue.Schemas.SignInWithIdToken
  alias Supabase.GoTrue.Schemas.SignInWithOauth
  alias Supabase.GoTrue.Schemas.SignInWithOTP
  alias Supabase.GoTrue.Schemas.SignInWithPassword
  alias Supabase.GoTrue.Schemas.SignInWithSSO
  alias Supabase.GoTrue.Schemas.SignUpWithPassword
  alias Supabase.GoTrue.Schemas.UserParams
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User
  alias Supabase.GoTrue.UserHandler

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

      iex> session = %Supabase.GoTrue.Session{access_token: "eyJhbG..."}
      iex> {:ok, user} = Supabase.GoTrue.get_user(client, session)
      iex> user.email
      "user@example.com"
      
      # If the session is invalid or expired
      iex> {:error, %Supabase.Error{code: :unauthorized}} = Supabase.GoTrue.get_user(client, invalid_session)
  """
  @impl true
  def get_user(%Client{} = client, %Session{} = session) do
    with {:ok, response} <- UserHandler.get_user(client, session.access_token) do
      User.parse(response.body)
    end
  end

  @doc """
  Signs in a user with ID token.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInWithIdToken` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignInWithIdToken{}
      iex> Supabase.GoTrue.sign_in_with_id_token(pid | client_name, credentials)
      {:ok, %Supabase.GoTrue.Session{}}
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

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInWithOauth` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignInWithOauth{}
      iex> Supabase.GoTrue.sign_in_with_oauth(pid | client_name, credentials)
      {:ok, atom, URI.t()}
  """
  @impl true
  def sign_in_with_oauth(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithOauth.parse(credentials) do
      url = UserHandler.get_url_for_provider(client, credentials)
      {:ok, credentials.provider, url}
    end
  end

  @doc """
  Signs in a user with OTP.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInWithOTP` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignInWithOTP{}
      iex> Supabase.GoTrue.sign_in_with_otp(pid | client_name, credentials)
      :ok
  """
  @impl true
  def sign_in_with_otp(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithOTP.parse(credentials) do
      UserHandler.sign_in_with_otp(client, credentials)
    end
  end

  @doc """
  Verifies an OTP code.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `params` - The parameters to use for the verification. Check `Supabase.GoTrue.Schemas.VerifyOTP` for more information.

  ## Examples
      iex> params = %Supabase.GoTrue.VerifyOTP{}
      iex> Supabase.GoTrue.verify_otp(pid | client_name, params)
      {:ok, %Supabase.GoTrue.Session{}}
  """
  @impl true
  def verify_otp(%Client{} = client, params) do
    with {:ok, response} <- UserHandler.verify_otp(client, params) do
      Session.parse(response.body)
    end
  end

  @doc """
  Signs in a user with SSO.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInWithSSO` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignInWithSSO{}
      iex> Supabase.GoTrue.sign_in_with_sso(pid | client_name, credentials)
      {:ok, %Supabase.GoTrue.Session{}}
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
    * `gotrue_meta_security` - Optional captcha details

  ## Returns

  * `{:ok, session}` - Successfully authenticated, returns session with tokens
  * `{:error, error}` - Authentication failed

  ## Examples

      # Sign in with email
      iex> credentials = %{email: "user@example.com", password: "secure-password"}
      iex> {:ok, session} = Supabase.GoTrue.sign_in_with_password(client, credentials)
      iex> session.access_token
      "eyJhbG..."
      
      # Sign in with phone
      iex> credentials = %{phone: "+15555550123", password: "secure-password"}
      iex> {:ok, session} = Supabase.GoTrue.sign_in_with_password(client, credentials)

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

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `opts` - The options to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInAnonymously` for more information.

  ## Examples
      iex> Supabase.GoTrue.sign_in_anonymously(pid | client_name, %{})
      {:ok, %Supabase.GoTrue.Session{}}
  """
  @spec sign_in_anonymously(Client.t(), Enumerable.t()) :: {:ok, Session.t()} | {:error, term}
  def sign_in_anonymously(%Client{} = client, opts \\ %{}) do
    with {:ok, params} <- SignInAnonymously.parse(Map.new(opts)),
         {:ok, resp} <- UserHandler.sign_in_anonymously(client, params) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Signs up a user with email/phone and password.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign up. Check `Supabase.GoTrue.Schemas.SignUpWithPassword` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignUpWithPassword{}
      iex> Supabase.GoTrue.sign_up(pid | client_name, credentials)
      {:ok, %Supabase.GoTrue.User{}}
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
    iex> Supabase.GoTrue.reset_password_for_email(client, "john@example.com", redirect_to: "http://localohst:4000/reset-pass")
    :ok
  """
  @spec reset_password_for_email(Client.t(), String.t(), opts) :: :ok | {:error, term}
        when opts:
               [redirect_to: String.t()]
               | [captcha_token: String.t()]
               | [redirect_to: String.t(), captcha_token: String.t()]
  def reset_password_for_email(%Client{} = client, email, opts) do
    UserHandler.recover_password(client, email, Map.new(opts))
  end

  @doc """
  Resends a signup confirm email for the given email address.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `email` - A valid user email address to recover password
    - `opts`:
      - `redirect_to`: the url where the user should be redirected to reset their password
      - `captcha_token`

  ## Examples
    iex> Supabase.GoTrue.resend(client, "john@example.com", redirect_to: "http://localohst:4000/reset-pass")
    :ok
  """
  @spec resend(Client.t(), String.t(), ResendParams.t()) :: :ok | {:error, term}
  def resend(%Client{} = client, email, opts) do
    with {:ok, params} <- ResendParams.parse(Map.new(opts)) do
      UserHandler.resend(client, email, params)
    end
  end

  @doc """
  Updates the current logged in user.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `conn` - The current `Plug.Conn` or `Phoenix.LiveView.Socket` to get current user
    - `attrs` - Check `UserParams`

  ## Examples
      iex> params = %{email: "another@example.com", password: "new-pass"}
      iex> Supabase.GoTrue.update_user(client, conn, params)
      {:ok, conn}
  """
  @spec update_user(Client.t(), conn, UserParams.t()) :: {:ok, conn} | {:error, term}
        when conn: Plug.Conn.t() | Phoenix.LiveView.Socket.t()
  def update_user(%Client{} = client, conn, attrs) do
    with {:ok, params} <- UserParams.parse(attrs) do
      if conn.assigns.current_user do
        UserHandler.update_user(client, conn, params)
      else
        {:error, :no_user_logged_in}
      end
    end
  end

  @doc """
  Exchanges a refresh token for a new session.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `refresh_token` - The refresh token to use for the request.

  ## Examples
      iex> Supabase.GoTrue.refresh_session(client, "refresh_token")
      {:ok, %Supabase.GoTrue.Session{}}
  """
  @spec refresh_session(Client.t(), refresh_token :: String.t()) ::
          {:ok, Session.t()} | {:error, term}
  def refresh_session(%Client{} = client, refresh_token) do
    with {:ok, resp} <- UserHandler.refresh_session(client, refresh_token) do
      Session.parse(resp.body)
    end
  end

  @doc """
  Retrieves the server health from the GoTrue API.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.

  ## Examples
      iex> Supabase.GoTrue.get_server_health(client)
      {:ok, %Supabase.GoTrue.ServerHealth{}}
  """
  @spec get_server_health(Client.t()) :: {:ok, ServerHealth.t()} | {:error, term}
  def get_server_health(%Client{} = client) do
    with {:ok, resp} <- UserHandler.get_server_health(client) do
      ServerHealth.parse(resp.body)
    end
  end

  @doc """
  Retrieves the server settings from the GoTrue API.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.

  ## Examples
      iex> Supabase.GoTrue.get_server_settings(client)
      {:ok, %Supabase.GoTrue.ServerSettings{}}
  """
  @spec get_server_settings(Client.t()) :: {:ok, ServerSettings.t()} | {:error, term}
  def get_server_settings(%Client{} = client) do
    with {:ok, resp} <- UserHandler.get_server_settings(client) do
      ServerSettings.parse(resp.body)
    end
  end

  @doc """
  Retrieves the auth module handle from the application configuration.
  Check https://hexdocs.pm/supabase_gotrue/readme.html#usage
  """
  def get_auth_module! do
    Application.get_env(:supabase_gotrue, :auth_module) ||
      raise(Supabase.GoTrue.MissingConfig, key: :auth_module)
  end

  @doc """
  Gets a URL to link a new identity to the authenticated user's account.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request.
    - `credentials` - The OAuth credentials to use for identity linking. Check `Supabase.GoTrue.Schemas.SignInWithOauth` for more information.

  ## Examples
      iex> session = %Supabase.GoTrue.Session{access_token: "example_token"}
      iex> credentials = %Supabase.GoTrue.SignInWithOauth{provider: :github}
      iex> Supabase.GoTrue.link_identity(client, session, credentials)
      {:ok, %{provider: :github, url: "https://..."}}
  """
  @spec link_identity(Client.t(), Session.t(), map) :: {:ok, map} | {:error, term}
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
      iex> session = %Supabase.GoTrue.Session{access_token: "example_token"}
      iex> identity_id = "1234567890"
      iex> Supabase.GoTrue.unlink_identity(client, session, identity_id)
      :ok
  """
  @spec unlink_identity(Client.t(), Session.t(), String.t()) :: :ok | {:error, term}
  def unlink_identity(%Client{} = client, %Session{} = session, identity_id) do
    UserHandler.unlink_identity(client, session.access_token, identity_id)
  end

  @doc """
  Gets all identities for the authenticated user.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request.

  ## Examples
      iex> session = %Supabase.GoTrue.Session{access_token: "example_token"}
      iex> Supabase.GoTrue.get_user_identities(client, session)
      {:ok, [%Supabase.GoTrue.User.Identity{}, ...]}
  """
  @spec get_user_identities(Client.t(), Session.t()) :: {:ok, list(User.Identity.t())} | {:error, term}
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
      iex> Supabase.GoTrue.exchange_code_for_session(client, auth_code, code_verifier)
      {:ok, %Supabase.GoTrue.Session{}}
  """
  @impl true
  @spec exchange_code_for_session(Client.t(), String.t(), String.t(), map()) ::
          {:ok, Session.t()} | {:error, term}
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
      iex> session = %Supabase.GoTrue.Session{access_token: "example_token"}
      iex> Supabase.GoTrue.reauthenticate(client, session)
      :ok
  """
  @impl true
  @spec reauthenticate(Client.t(), Session.t()) :: :ok | {:error, term}
  def reauthenticate(%Client{} = client, %Session{} = session) do
    UserHandler.reauthenticate(client, session.access_token)
  end
end
