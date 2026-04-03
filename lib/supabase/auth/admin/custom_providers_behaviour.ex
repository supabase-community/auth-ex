defmodule Supabase.Auth.Admin.CustomProviders.Behaviour do
  @moduledoc """
  Behaviour for admin-level custom OIDC/OAuth provider management.

  Defines the contract for managing custom identity providers programmatically
  via the GoTrue admin API. Requires a service_role key.
  """

  alias Supabase.Auth.Schemas.CustomProvider
  alias Supabase.Client

  @callback list_providers(Client.t(), map()) ::
              {:ok, [CustomProvider.t()]} | {:error, term()}

  @callback create_provider(Client.t(), map()) ::
              {:ok, CustomProvider.t()} | {:error, term()}

  @callback get_provider(Client.t(), String.t()) ::
              {:ok, CustomProvider.t()} | {:error, term()}

  @callback update_provider(Client.t(), String.t(), map()) ::
              {:ok, CustomProvider.t()} | {:error, term()}

  @callback delete_provider(Client.t(), String.t()) ::
              :ok | {:error, term()}
end
