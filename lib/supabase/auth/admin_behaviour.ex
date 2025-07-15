defmodule Supabase.Auth.AdminBehaviour do
  @moduledoc """
  Behaviour specification for the Supabase.Auth.Admin module.

  This module defines the contract that any Auth Admin implementation must fulfill,
  providing function specifications and return types for all admin operations.
  """

  alias Supabase.Auth.Session
  alias Supabase.Auth.User
  alias Supabase.Client

  @type scope :: :global | :local | :others
  @type invite_options :: %{optional(:data) => map(), optional(:redirect_to) => String.t()}
  @type pagination :: %{next_page: integer() | nil, last_page: integer(), total: integer()}

  @callback sign_out(Client.t(), Session.t(), scope) :: :ok | {:error, term()}

  @callback invite_user_by_email(Client.t(), String.t(), invite_options()) ::
              {:ok, User.t()} | {:error, term()}

  @callback generate_link(Client.t(), map()) ::
              {:ok,
               %{
                 action_link: String.t(),
                 email_otp: String.t(),
                 hashed_token: String.t(),
                 redirect_to: String.t(),
                 verification_type: atom()
               }}
              | {:error, term()}

  @callback create_user(Client.t(), map()) :: {:ok, User.t()} | {:error, term()}

  @callback list_users(Client.t(), map()) ::
              {:ok, list(User.t()), pagination()} | {:error, term()}

  @callback get_user_by_id(Client.t(), String.t()) :: {:ok, User.t()} | {:error, term()}

  @callback update_user_by_id(Client.t(), String.t(), map()) ::
              {:ok, User.t()} | {:error, term()}

  @callback delete_user(Client.t(), String.t(), keyword()) :: :ok | {:error, term()}

  @callback delete_factor(Client.t(), String.t(), String.t()) :: :ok | {:error, term()}

  @callback list_identities(Client.t(), String.t()) ::
              {:ok, list(User.Identity.t())} | {:error, term()}

  @callback delete_identity(Client.t(), String.t(), String.t()) :: :ok | {:error, term()}
end
