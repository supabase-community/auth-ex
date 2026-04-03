defmodule Supabase.Auth.Schemas.CreateCustomProviderParamsTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.CreateCustomProviderParams

  describe "parse/1" do
    test "successfully parses with required fields" do
      attrs = %{
        provider_type: "oidc",
        identifier: "custom:mycompany",
        name: "My Company SSO",
        client_id: "oauth-client-id",
        client_secret: "oauth-client-secret"
      }

      assert {:ok, params} = CreateCustomProviderParams.parse(attrs)
      assert params.provider_type == "oidc"
      assert params.identifier == "custom:mycompany"
    end

    test "successfully parses with all optional fields" do
      attrs = %{
        provider_type: "oidc",
        identifier: "custom:mycompany",
        name: "My Company SSO",
        client_id: "id",
        client_secret: "secret",
        scopes: ["openid"],
        pkce_enabled: true,
        issuer: "https://sso.example.com",
        enabled: true
      }

      assert {:ok, params} = CreateCustomProviderParams.parse(attrs)
      assert params.pkce_enabled == true
    end

    test "returns error when required fields are missing" do
      assert {:error, changeset} = CreateCustomProviderParams.parse(%{})
      errors = errors_on(changeset)
      assert errors[:provider_type]
      assert errors[:identifier]
      assert errors[:name]
      assert errors[:client_id]
      assert errors[:client_secret]
    end

    test "returns error for invalid provider_type" do
      attrs = %{
        provider_type: "invalid",
        identifier: "custom:test",
        name: "Test",
        client_id: "id",
        client_secret: "secret"
      }

      assert {:error, changeset} = CreateCustomProviderParams.parse(attrs)
      assert %{provider_type: [_]} = errors_on(changeset)
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
