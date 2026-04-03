defmodule Supabase.Auth.Admin.OAuth do
  @moduledoc """
  Admin OAuth 2.1 client management for Supabase Auth.

  Provides functions to manage OAuth clients programmatically via the admin API.
  All operations require a client configured with a `service_role` key.

  Only relevant when the OAuth 2.1 server is enabled in Supabase Auth.

  ## Client Lifecycle

      # Create a new OAuth client
      {:ok, client} = Admin.OAuth.create_client(supabase, %{
        client_name: "My App",
        redirect_uris: ["https://myapp.com/callback"]
      })

      # List all clients
      {:ok, clients, pagination} = Admin.OAuth.list_clients(supabase)

      # Update a client
      {:ok, updated} = Admin.OAuth.update_client(supabase, client.client_id, %{
        client_name: "My Renamed App"
      })

      # Regenerate client secret
      {:ok, rotated} = Admin.OAuth.regenerate_client_secret(supabase, client.client_id)

      # Delete a client
      :ok = Admin.OAuth.delete_client(supabase, client.client_id)
  """

  @behaviour Supabase.Auth.Admin.OAuth.Behaviour

  alias Supabase.Auth.Admin.OAuthHandler
  alias Supabase.Auth.Schemas.OAuth.AdminClient
  alias Supabase.Auth.Schemas.OAuth.CreateClientParams
  alias Supabase.Auth.Schemas.OAuth.UpdateClientParams
  alias Supabase.Auth.Schemas.PaginationParams
  alias Supabase.Client
  alias Supabase.Fetcher.Response

  @doc """
  Lists all OAuth clients with optional pagination.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `params` - Optional pagination parameters:
      * `page` - Page number (default: 1)
      * `per_page` - Number of clients per page

  ## Returns
    * `{:ok, clients, pagination}` - List of OAuth clients with pagination info
    * `{:error, error}` - Failed to list clients

  ## Examples
      iex> Supabase.Auth.Admin.OAuth.list_clients(client)
      {:ok, [%{client_id: "...", client_name: "My App", ...}], %{next_page: 2, last_page: 5, total: 42}}
  """
  @impl true
  def list_clients(%Client{} = client, params \\ %{}) do
    with {:ok, params} <- PaginationParams.page_params(Map.new(params)),
         {:ok, response} <- OAuthHandler.list_clients(client, params),
         {:ok, clients} <- AdminClient.parse_list(response.body["clients"] || []) do
      total = Response.get_header(response, "x-total-count")

      links =
        response
        |> Response.get_header("link", "")
        |> String.split(",", trim: true)

      next = parse_page_count(links, ~r/.+\?page=(\d).+rel=\"next\"/)
      last = parse_page_count(links, ~r/.+\?page=(\d).+rel=\"last\"/)

      attrs = %{next_page: (next != 0 && next) || nil, last_page: last, total: total}
      {:ok, pagination} = PaginationParams.pagination(attrs)

      {:ok, clients, pagination}
    end
  end

  @doc """
  Creates a new OAuth client.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The client attributes:
      * `client_name` - Human-readable name (required)
      * `redirect_uris` - List of allowed redirect URIs (required, min 1)
      * `client_uri` - URI of the OAuth client
      * `grant_types` - Allowed grant types (defaults to `["authorization_code", "refresh_token"]`)
      * `response_types` - Allowed response types (defaults to `["code"]`)
      * `scope` - Scope string
      * `token_endpoint_auth_method` - One of `"none"`, `"client_secret_basic"`, `"client_secret_post"`

  ## Returns
    * `{:ok, oauth_client}` - The created client (includes `client_secret`)
    * `{:error, error}` - Failed to create client

  ## Examples
      iex> attrs = %{client_name: "My App", redirect_uris: ["https://myapp.com/callback"]}
      iex> Supabase.Auth.Admin.OAuth.create_client(client, attrs)
      {:ok, %{client_id: "...", client_name: "My App", client_secret: "...", ...}}
  """
  @impl true
  def create_client(%Client{} = client, attrs) do
    with {:ok, params} <- CreateClientParams.parse(attrs),
         {:ok, response} <- OAuthHandler.create_client(client, params) do
      AdminClient.parse(response.body)
    end
  end

  @doc """
  Gets details of a specific OAuth client.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `client_id` - The ID of the OAuth client to retrieve.

  ## Returns
    * `{:ok, oauth_client}` - The OAuth client details
    * `{:error, error}` - Failed to retrieve client

  ## Examples
      iex> Supabase.Auth.Admin.OAuth.get_client(client, "client-uuid")
      {:ok, %{client_id: "client-uuid", client_name: "My App", ...}}
  """
  @impl true
  def get_client(%Client{} = client, client_id) do
    with {:ok, response} <- OAuthHandler.get_client(client, client_id) do
      AdminClient.parse(response.body)
    end
  end

  @doc """
  Updates an existing OAuth client.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `client_id` - The ID of the OAuth client to update.
    * `attrs` - The attributes to update (all optional):
      * `client_name` - Human-readable name
      * `client_uri` - URI of the OAuth client
      * `logo_uri` - URI of the client's logo
      * `redirect_uris` - List of allowed redirect URIs
      * `grant_types` - Allowed grant types
      * `token_endpoint_auth_method` - Token endpoint auth method

  ## Returns
    * `{:ok, oauth_client}` - The updated client
    * `{:error, error}` - Failed to update client

  ## Examples
      iex> Supabase.Auth.Admin.OAuth.update_client(client, "client-uuid", %{client_name: "New Name"})
      {:ok, %{client_id: "client-uuid", client_name: "New Name", ...}}
  """
  @impl true
  def update_client(%Client{} = client, client_id, attrs) do
    with {:ok, params} <- UpdateClientParams.parse(attrs),
         {:ok, response} <- OAuthHandler.update_client(client, client_id, params) do
      AdminClient.parse(response.body)
    end
  end

  @doc """
  Deletes an OAuth client.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `client_id` - The ID of the OAuth client to delete.

  ## Returns
    * `:ok` - Successfully deleted the client
    * `{:error, error}` - Failed to delete client

  ## Examples
      iex> Supabase.Auth.Admin.OAuth.delete_client(client, "client-uuid")
      :ok
  """
  @impl true
  def delete_client(%Client{} = client, client_id) do
    with {:ok, _} <- OAuthHandler.delete_client(client, client_id), do: :ok
  end

  @doc """
  Regenerates the secret for an OAuth client.

  The previous secret is immediately invalidated.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `client_id` - The ID of the OAuth client.

  ## Returns
    * `{:ok, oauth_client}` - The client with the new `client_secret`
    * `{:error, error}` - Failed to regenerate secret

  ## Examples
      iex> Supabase.Auth.Admin.OAuth.regenerate_client_secret(client, "client-uuid")
      {:ok, %{client_id: "client-uuid", client_secret: "new-secret-...", ...}}
  """
  @impl true
  def regenerate_client_secret(%Client{} = client, client_id) do
    with {:ok, response} <- OAuthHandler.regenerate_client_secret(client, client_id) do
      AdminClient.parse(response.body)
    end
  end

  defp parse_page_count(links, regex) do
    Enum.reduce_while(links, 0, fn link, acc ->
      case Regex.run(regex, link) do
        [_, page] -> {:halt, page}
        _ -> {:cont, acc}
      end
    end)
  end
end
