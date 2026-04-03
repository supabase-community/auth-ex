defmodule Supabase.Auth.Admin.CustomProviderFixture do
  @moduledoc """
  Fixtures for Admin custom provider testing.
  """

  def custom_provider_fixture(attrs \\ []) do
    defaults = %{
      "id" => "provider-uuid-123",
      "provider_type" => "oidc",
      "identifier" => "custom:mycompany",
      "name" => "My Company SSO",
      "client_id" => "oauth-client-id",
      "scopes" => ["openid", "profile", "email"],
      "pkce_enabled" => true,
      "enabled" => true,
      "email_optional" => false,
      "issuer" => "https://sso.mycompany.com",
      "discovery_url" => "https://sso.mycompany.com/.well-known/openid-configuration",
      "skip_nonce_check" => false,
      "discovery_document" => %{
        "issuer" => "https://sso.mycompany.com",
        "authorization_endpoint" => "https://sso.mycompany.com/authorize",
        "token_endpoint" => "https://sso.mycompany.com/token",
        "jwks_uri" => "https://sso.mycompany.com/.well-known/jwks.json"
      },
      "created_at" => "2024-01-01T00:00:00Z",
      "updated_at" => "2024-01-01T00:00:00Z"
    }

    Map.merge(defaults, Map.new(attrs, fn {k, v} -> {to_string(k), v} end))
  end

  def custom_provider_fixture_json(attrs \\ []) do
    json = Supabase.json_library()
    attrs |> custom_provider_fixture() |> json.encode!()
  end

  def custom_provider_list_fixture_json(providers \\ nil) do
    json = Supabase.json_library()

    providers =
      providers ||
        [
          custom_provider_fixture(),
          custom_provider_fixture(
            id: "provider-uuid-456",
            identifier: "custom:partner",
            name: "Partner SSO",
            provider_type: "oauth2"
          )
        ]

    json.encode!(%{"providers" => providers})
  end
end
