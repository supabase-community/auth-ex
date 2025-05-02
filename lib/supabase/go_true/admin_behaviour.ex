defmodule Supabase.GoTrue.AdminBehaviour do
  @moduledoc false

  alias Supabase.Client
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  @type scope :: :global | :local | :others
  @type invite_options :: %{data: map, redirect_to: String.t()}

  @callback sign_out(Client.t(), Session.t(), scope) :: :ok | {:error, Supabase.Error.t()}
  @callback invite_user_by_email(Client.t(), email, invite_options) ::
              :ok | {:error, Supabase.Error.t()}
            when email: String.t()
  @callback generate_link(Client.t(), map) :: Supabase.result(String.t())
  @callback create_user(Client.t(), map) :: Supabase.result(User.t())
  @callback list_users(Client.t()) :: Supabase.result(list(User.t()))
  @callback get_user_by_id(Client.t(), Ecto.UUID.t()) :: Supabase.result(User.t())
  @callback update_user_by_id(Client.t(), Ecto.UUID.t(), map) :: Supabase.result(User.t())
  @callback delete_user(Client.t(), Ecto.UUID.t(), keyword) :: Supabase.result(User.t())
  @callback delete_factor(Client.t(), Ecto.UUID.t(), String.t()) :: :ok | {:error, Supabase.Error.t()}
  @callback list_identities(Client.t(), Ecto.UUID.t()) :: Supabase.result(list(User.Identity.t()))
  @callback delete_identity(Client.t(), Ecto.UUID.t(), String.t()) :: :ok | {:error, Supabase.Error.t()}
end
