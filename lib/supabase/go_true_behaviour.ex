defmodule Supabase.GoTrueBehaviour do
  @moduledoc false

  alias Supabase.Client
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  @type sign_in_response :: Supabase.result(Session.t()) | {:error, Ecto.Changeset.t()}

  @callback get_user(Client.t(), Session.t()) :: Supabase.result(User.t())
  @callback sign_in_with_oauth(Client.t(), map) ::
              {:ok, atom, URI.t()} | {:error, Supabase.Error.t()}
  @callback verify_otp(Client.t(), map) :: sign_in_response
  @callback sign_in_with_otp(Client.t(), map) :: :ok | Supabase.result(Ecto.UUID.t())
  @callback sign_in_with_sso(Client.t(), map) :: Supabase.result(URI.t())
  @callback sign_in_with_id_token(Client.t(), map) :: sign_in_response
  @callback sign_in_with_password(Client.t(), map) :: sign_in_response
  @callback sign_up(Client.t(), map) :: {:ok, User.t(), binary} | {:error, Supabase.Error.t()}
end
