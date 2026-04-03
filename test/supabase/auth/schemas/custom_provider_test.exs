defmodule Supabase.Auth.Schemas.CustomProviderTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.CustomProvider

  @valid_attrs %{
    "id" => "provider-123",
    "provider_type" => "oidc",
    "identifier" => "custom:mycompany",
    "name" => "My Company SSO",
    "client_id" => "oauth-client-id",
    "created_at" => "2024-01-01T00:00:00Z",
    "updated_at" => "2024-01-01T00:00:00Z"
  }

  describe "parse/1" do
    test "successfully parses valid provider data" do
      attrs =
        Map.merge(@valid_attrs, %{
          "scopes" => ["openid", "profile"],
          "issuer" => "https://sso.mycompany.com",
          "enabled" => true
        })

      assert {:ok, provider} = CustomProvider.parse(attrs)
      assert provider.id == "provider-123"
      assert provider.provider_type == "oidc"
      assert provider.identifier == "custom:mycompany"
      assert provider.scopes == ["openid", "profile"]
    end

    test "successfully parses with only required fields" do
      assert {:ok, provider} = CustomProvider.parse(@valid_attrs)
      assert provider.id == "provider-123"
      assert provider.provider_type == "oidc"
    end

    test "returns error when required fields are missing" do
      assert {:error, changeset} = CustomProvider.parse(%{})
      errors = errors_on(changeset)
      assert errors[:id]
      assert errors[:provider_type]
      assert errors[:identifier]
      assert errors[:name]
      assert errors[:client_id]
      assert errors[:created_at]
      assert errors[:updated_at]
    end

    test "returns error for invalid provider_type" do
      attrs = Map.put(@valid_attrs, "provider_type", "invalid")
      assert {:error, changeset} = CustomProvider.parse(attrs)
      assert %{provider_type: [_]} = errors_on(changeset)
    end
  end

  describe "parse_list/1" do
    test "successfully parses a list of providers" do
      data = [
        @valid_attrs,
        Map.merge(@valid_attrs, %{
          "id" => "provider-456",
          "identifier" => "custom:partner",
          "provider_type" => "oauth2"
        })
      ]

      assert {:ok, providers} = CustomProvider.parse_list(data)
      assert length(providers) == 2
    end

    test "returns error if any provider is invalid" do
      assert {:error, _} = CustomProvider.parse_list([@valid_attrs, %{}])
    end

    test "successfully parses empty list" do
      assert {:ok, []} = CustomProvider.parse_list([])
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
