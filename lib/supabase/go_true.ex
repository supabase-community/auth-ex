defmodule Supabase.GoTrue do
  @moduledoc """
  This module provides the functionality to interact with the GoTrue API,
  allowing management of users, sessions, and authentication.

  It also aims to provide integrations with Plug and Phoenix LiveView applications.

  For detailed information about the GoTrue API, check the official documentation at https://supabase.io/docs/reference/javascript/auth-api

  And also refer to functions and submodules documentation for more information.
  """

  alias Supabase.Client
  alias Supabase.GoTrue.Schemas.ResendParams
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

  @behaviour Supabase.GoTrueBehaviour

  @doc """
  Get the user associated with the current session.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `session` - The session to use for the request. Check `Supabase.GoTrue.Session` for more information.

  ## Examples
      iex> session = %Supabase.GoTrue.Session{access_token: "example_token"}
      iex> Supabase.GoTrue.get_user(pid | client_name, session)
      {:ok, %Supabase.GoTrue.User{}}
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
  Signs in a user with email/phone and password.

  ## Parameters
    - `client` - The `Supabase` client to use for the request.
    - `credentials` - The credentials to use for the sign in. Check `Supabase.GoTrue.Schemas.SignInWithPassword` for more information.

  ## Examples
      iex> credentials = %Supabase.GoTrue.SignInWithPassword{}
      iex> Supabase.GoTrue.sign_in_with_password(pid | client_name, credentials)
      {:ok, %Supabase.GoTrue.Session{}}
  """
  @impl true
  def sign_in_with_password(%Client{} = client, credentials) do
    with {:ok, credentials} <- SignInWithPassword.parse(credentials),
         {:ok, response} <- UserHandler.sign_in_with_password(client, credentials) do
      Session.parse(response.body)
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
  Retrieves the auth module handle from the application configuration.
  Check https://hexdocs.pm/supabase_gotrue/readme.html#usage
  """
  def get_auth_module! do
    Application.get_env(:supabase_gotrue, :auth_module) ||
      raise(Supabase.GoTrue.MissingConfig, key: :auth_module)
  end
end
