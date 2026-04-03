defmodule Supabase.Auth.Admin.CustomProviders do
  @moduledoc """
  Admin custom OIDC/OAuth provider management for Supabase Auth.

  Provides functions to manage custom identity providers programmatically
  via the admin API. All operations require a client configured with a
  `service_role` key.

  ## Provider Types

    * `"oidc"` — OpenID Connect providers. The server fetches and validates
      the discovery document from the issuer's well-known endpoint at
      creation/update time.
    * `"oauth2"` — Generic OAuth 2.0 providers. Requires explicit endpoint URLs.

  ## Examples

      # Create an OIDC provider
      {:ok, provider} = Admin.CustomProviders.create_provider(client, %{
        provider_type: "oidc",
        identifier: "custom:mycompany",
        name: "My Company SSO",
        client_id: "abc123",
        client_secret: "secret",
        issuer: "https://sso.mycompany.com"
      })

      # List all providers
      {:ok, providers} = Admin.CustomProviders.list_providers(client)

      # List only OIDC providers
      {:ok, providers} = Admin.CustomProviders.list_providers(client, %{type: "oidc"})

      # Update a provider
      {:ok, updated} = Admin.CustomProviders.update_provider(client, "custom:mycompany", %{
        name: "My Company SSO v2"
      })

      # Delete a provider
      :ok = Admin.CustomProviders.delete_provider(client, "custom:mycompany")
  """

  @behaviour Supabase.Auth.Admin.CustomProviders.Behaviour

  alias Supabase.Auth.Admin.CustomProvidersHandler
  alias Supabase.Auth.Schemas.CreateCustomProviderParams
  alias Supabase.Auth.Schemas.CustomProvider
  alias Supabase.Auth.Schemas.UpdateCustomProviderParams
  alias Supabase.Client

  @doc """
  Lists all custom providers with optional type filter.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `params` - Optional filter parameters:
      * `type` - Filter by provider type: `"oidc"` or `"oauth2"`

  ## Returns
    * `{:ok, providers}` - List of custom providers
    * `{:error, error}` - Failed to list providers

  ## Examples
      iex> Supabase.Auth.Admin.CustomProviders.list_providers(client)
      {:ok, [%{id: "...", identifier: "custom:mycompany", ...}]}

      iex> Supabase.Auth.Admin.CustomProviders.list_providers(client, %{type: "oidc"})
      {:ok, [%{provider_type: "oidc", ...}]}
  """
  @impl true
  def list_providers(%Client{} = client, params \\ %{}) do
    with {:ok, response} <- CustomProvidersHandler.list_providers(client, Map.new(params)) do
      CustomProvider.parse_list(response.body["providers"] || [])
    end
  end

  @doc """
  Creates a new custom OIDC/OAuth provider.

  For OIDC providers, the server fetches and validates the OpenID Connect
  discovery document from the issuer's well-known endpoint at creation time.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The provider attributes:
      * `provider_type` - `"oidc"` or `"oauth2"` (required)
      * `identifier` - Provider identifier, e.g. `"custom:mycompany"` (required)
      * `name` - Human-readable name (required)
      * `client_id` - OAuth client ID (required)
      * `client_secret` - OAuth client secret (required, write-only)
      * `issuer` - OIDC issuer URL (required for OIDC)
      * `scopes` - List of OAuth scopes
      * `pkce_enabled` - Whether to use PKCE
      * `attribute_mapping` - Map of provider attributes to user attributes
      * `authorization_params` - Additional authorization request params
      * `enabled` - Whether the provider is enabled
      * `email_optional` - Whether email is optional
      * `discovery_url` - Custom OIDC discovery URL
      * `skip_nonce_check` - Whether to skip nonce validation (OIDC)
      * `authorization_url` - OAuth2 authorization endpoint (for oauth2 type)
      * `token_url` - OAuth2 token endpoint (for oauth2 type)
      * `userinfo_url` - OAuth2 userinfo endpoint (for oauth2 type)
      * `jwks_uri` - JWKS URI for token verification

  ## Returns
    * `{:ok, provider}` - The created provider
    * `{:error, error}` - Failed to create provider
  """
  @impl true
  def create_provider(%Client{} = client, attrs) do
    with {:ok, params} <- CreateCustomProviderParams.parse(attrs),
         {:ok, response} <- CustomProvidersHandler.create_provider(client, params) do
      CustomProvider.parse(response.body)
    end
  end

  @doc """
  Gets details of a specific custom provider by identifier.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `identifier` - The provider identifier (e.g. `"custom:mycompany"`).

  ## Returns
    * `{:ok, provider}` - The provider details
    * `{:error, error}` - Failed to retrieve provider
  """
  @impl true
  def get_provider(%Client{} = client, identifier) do
    with {:ok, response} <- CustomProvidersHandler.get_provider(client, identifier) do
      CustomProvider.parse(response.body)
    end
  end

  @doc """
  Updates an existing custom provider.

  When `issuer` or `discovery_url` is changed on an OIDC provider, the server
  re-fetches and validates the discovery document before persisting.

  Note: `provider_type` and `identifier` are immutable and cannot be changed.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `identifier` - The provider identifier.
    * `attrs` - The attributes to update (all optional).

  ## Returns
    * `{:ok, provider}` - The updated provider
    * `{:error, error}` - Failed to update provider
  """
  @impl true
  def update_provider(%Client{} = client, identifier, attrs) do
    with {:ok, params} <- UpdateCustomProviderParams.parse(attrs),
         {:ok, response} <- CustomProvidersHandler.update_provider(client, identifier, params) do
      CustomProvider.parse(response.body)
    end
  end

  @doc """
  Deletes a custom provider.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `identifier` - The provider identifier.

  ## Returns
    * `:ok` - Successfully deleted the provider
    * `{:error, error}` - Failed to delete provider
  """
  @impl true
  def delete_provider(%Client{} = client, identifier) do
    with {:ok, _} <- CustomProvidersHandler.delete_provider(client, identifier), do: :ok
  end
end
