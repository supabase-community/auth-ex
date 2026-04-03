defmodule Supabase.Auth.Admin.OAuthClientFixture do
  @moduledoc """
  Fixtures for Admin OAuth client testing.
  """

  @doc """
  Generates an admin OAuth client fixture as a map.
  """
  def admin_oauth_client_fixture(attrs \\ []) do
    defaults = %{
      "client_id" => "client-uuid-123",
      "client_name" => "Test Application",
      "client_secret" => "secret-abc-123",
      "client_type" => "confidential",
      "token_endpoint_auth_method" => "client_secret_basic",
      "registration_type" => "manual",
      "client_uri" => "https://example.com",
      "logo_uri" => "https://example.com/logo.png",
      "redirect_uris" => ["https://example.com/callback"],
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "scope" => "openid profile",
      "created_at" => "2024-01-01T00:00:00Z",
      "updated_at" => "2024-01-01T00:00:00Z"
    }

    Map.merge(defaults, Map.new(attrs, fn {k, v} -> {to_string(k), v} end))
  end

  @doc """
  Generates an admin OAuth client fixture as JSON string.
  """
  def admin_oauth_client_fixture_json(attrs \\ []) do
    json = Supabase.json_library()
    attrs |> admin_oauth_client_fixture() |> json.encode!()
  end

  @doc """
  Generates a list of admin OAuth clients as JSON string.
  """
  def admin_oauth_client_list_fixture_json(clients \\ nil) do
    json = Supabase.json_library()

    clients =
      clients ||
        [
          admin_oauth_client_fixture(),
          admin_oauth_client_fixture(
            client_id: "client-uuid-456",
            client_name: "Another App"
          )
        ]

    json.encode!(%{"clients" => clients})
  end
end
