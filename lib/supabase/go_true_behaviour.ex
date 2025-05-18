defmodule Supabase.GoTrueBehaviour do
  @moduledoc """
  Behaviour specification for the Supabase.GoTrue module.

  This module defines the contract that any GoTrue implementation must fulfill,
  providing function specifications and return types for all authentication operations.
  """

  alias Supabase.Client
  alias Supabase.GoTrue.Schemas.ResendParams
  alias Supabase.GoTrue.Schemas.ServerHealth
  alias Supabase.GoTrue.Schemas.ServerSettings
  alias Supabase.GoTrue.Schemas.SignInAnonymously
  alias Supabase.GoTrue.Schemas.UserParams
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  @type sign_in_response :: {:ok, Session.t()} | {:error, term()}
  @type conn :: Plug.Conn.t() | Phoenix.LiveView.Socket.t()

  @callback get_user(Client.t(), Session.t()) :: {:ok, User.t()} | {:error, term()}

  @callback sign_in_with_id_token(Client.t(), map()) :: sign_in_response

  @callback sign_in_with_oauth(Client.t(), map()) ::
              {:ok, atom(), String.t()} | {:error, term()}

  @callback sign_in_with_otp(Client.t(), map()) :: :ok | {:ok, String.t()} | {:error, term()}

  @callback verify_otp(Client.t(), map()) :: sign_in_response

  @callback sign_in_with_sso(Client.t(), map()) :: {:ok, String.t()} | {:error, term()}

  @callback sign_in_with_password(Client.t(), map()) :: sign_in_response

  @callback sign_in_anonymously(Client.t(), SignInAnonymously.t()) :: sign_in_response

  @callback sign_up(Client.t(), map()) :: {:ok, User.t()} | {:error, term()}

  @callback reset_password_for_email(Client.t(), String.t(), opts) :: :ok | {:error, term()}
            when opts:
                   [redirect_to: String.t()]
                   | [captcha_token: String.t()]
                   | [redirect_to: String.t(), captcha_token: String.t()]

  @callback resend(Client.t(), String.t(), ResendParams.t()) :: :ok | {:error, term()}

  @callback update_user(Client.t(), conn, UserParams.t()) :: {:ok, conn} | {:error, term()}

  @callback refresh_session(Client.t(), String.t()) :: sign_in_response

  @callback get_server_health(Client.t()) :: {:ok, ServerHealth.t()} | {:error, term()}

  @callback get_server_settings(Client.t()) :: {:ok, ServerSettings.t()} | {:error, term()}

  @callback link_identity(Client.t(), Session.t(), map()) :: {:ok, map()} | {:error, term()}

  @callback unlink_identity(Client.t(), Session.t(), String.t()) :: :ok | {:error, term()}

  @callback get_user_identities(Client.t(), Session.t()) ::
              {:ok, list(User.Identity.t())} | {:error, term()}

  @callback exchange_code_for_session(Client.t(), String.t(), String.t(), map()) :: sign_in_response

  @callback reauthenticate(Client.t(), Session.t()) :: :ok | {:error, term()}
end
