defmodule Supabase.GoTrue do
  @moduledoc deprecated: "Use Supabase.Auth instead", since: "0.6.0"

  alias Supabase.Auth

  defdelegate get_user(client, session), to: Auth

  defdelegate sign_in_with_id_token(client, cred), to: Auth

  defdelegate sign_in_with_oauth(client, cred), to: Auth

  defdelegate sign_in_with_otp(client, cred), to: Auth

  defdelegate verify_otp(client, params), to: Auth

  defdelegate sign_in_with_sso(client, cred), to: Auth

  defdelegate sign_in_with_password(client, cred), to: Auth

  defdelegate sign_in_anonymously(client, opts \\ %{}), to: Auth

  defdelegate sign_up(client, cred), to: Auth

  defdelegate reset_password_for_email(client, email, opts), to: Auth

  defdelegate resend(client, email, opts), to: Auth

  defdelegate update_user(client, conn, attrs), to: Auth

  defdelegate refresh_session(client, refresh_token), to: Auth

  defdelegate get_server_health(client), to: Auth

  defdelegate get_server_settings(client), to: Auth

  defdelegate link_identity(client, session, credentials), to: Auth

  defdelegate unlink_identity(client, session, identity_id), to: Auth

  defdelegate get_user_identities(client, session), to: Auth

  defdelegate exchange_code_for_session(client, auth_code, code_verifier, opts \\ %{}), to: Auth

  defdelegate reauthenticate(client, session), to: Auth
end
