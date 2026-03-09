defmodule Supabase.Auth.OAuthFixture do
  @moduledoc """
  Fixtures for OAuth testing.
  """

  @doc """
  Generates an OAuth client fixture.
  """
  def client_fixture(attrs \\ %{}) do
    default = %{
      "id" => "client-id-123",
      "name" => "Test Application",
      "uri" => "https://example.com",
      "logo_uri" => "https://example.com/logo.png"
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc """
  Generates an OAuth grant fixture.
  """
  def grant_fixture(attrs \\ %{}) do
    default = %{
      "client" => client_fixture(),
      "scopes" => ["read", "write"],
      "granted_at" => "2024-01-01T00:00:00Z"
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc """
  Generates a list of OAuth grants as JSON.
  """
  def grant_list_fixture_json(grants \\ nil) do
    json = Supabase.json_library()

    grants =
      grants ||
        [
          grant_fixture(),
          grant_fixture(%{"client" => client_fixture(%{"id" => "client-456", "name" => "Another App"})})
        ]

    json.encode!(grants)
  end

  @doc """
  Generates OAuth authorization details fixture.
  """
  def authorization_details_fixture(attrs \\ %{}) do
    default = %{
      "authorization_id" => "auth-id-123",
      "redirect_url" => nil,
      "client" => client_fixture(),
      "user" => %{
        "id" => "user-id-123",
        "email" => "user@example.com"
      },
      "scope" => "read write"
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc """
  Generates OAuth authorization details with early-exit (redirect_url present).
  """
  def authorization_details_early_exit_fixture(attrs \\ %{}) do
    authorization_details_fixture(
      Map.merge(%{"redirect_url" => "https://example.com/callback?code=abc123"}, Map.new(attrs))
    )
  end

  @doc """
  Generates OAuth consent response fixture.
  """
  def consent_response_fixture(attrs \\ %{}) do
    default = %{
      "redirect_url" => "https://example.com/callback?code=xyz789"
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc """
  Generates OAuth authorization details as JSON.
  """
  def authorization_details_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> authorization_details_fixture() |> json.encode!()
  end

  @doc """
  Generates OAuth consent response as JSON.
  """
  def consent_response_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> consent_response_fixture() |> json.encode!()
  end
end
