defmodule Supabase.Auth.Admin.OAuth.Behaviour do
  @moduledoc """
  Behaviour for admin-level OAuth 2.1 client management operations.

  Defines the contract for managing OAuth clients programmatically via
  the GoTrue admin API. Requires a service_role key.
  """

  alias Supabase.Auth.Schemas.OAuth.AdminClient
  alias Supabase.Client

  @type pagination :: %{next_page: integer() | nil, last_page: integer(), total: integer()}

  @callback list_clients(Client.t(), map()) ::
              {:ok, [AdminClient.t()], pagination()} | {:error, term()}

  @callback create_client(Client.t(), map()) ::
              {:ok, AdminClient.t()} | {:error, term()}

  @callback get_client(Client.t(), String.t()) ::
              {:ok, AdminClient.t()} | {:error, term()}

  @callback update_client(Client.t(), String.t(), map()) ::
              {:ok, AdminClient.t()} | {:error, term()}

  @callback delete_client(Client.t(), String.t()) ::
              :ok | {:error, term()}

  @callback regenerate_client_secret(Client.t(), String.t()) ::
              {:ok, AdminClient.t()} | {:error, term()}
end
