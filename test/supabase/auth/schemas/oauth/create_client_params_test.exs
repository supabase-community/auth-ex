defmodule Supabase.Auth.Schemas.OAuth.CreateClientParamsTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.CreateClientParams

  describe "parse/1" do
    test "successfully parses with required fields" do
      attrs = %{client_name: "My App", redirect_uris: ["https://example.com/callback"]}
      assert {:ok, params} = CreateClientParams.parse(attrs)
      assert params.client_name == "My App"
      assert params.redirect_uris == ["https://example.com/callback"]
    end

    test "successfully parses with all optional fields" do
      attrs = %{
        client_name: "My App",
        redirect_uris: ["https://example.com/callback"],
        client_uri: "https://example.com",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        token_endpoint_auth_method: "client_secret_basic"
      }

      assert {:ok, params} = CreateClientParams.parse(attrs)
      assert params.client_name == "My App"
      assert params.scope == "openid"
    end

    test "returns error when client_name is missing" do
      attrs = %{redirect_uris: ["https://example.com/callback"]}
      assert {:error, changeset} = CreateClientParams.parse(attrs)
      assert %{client_name: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when redirect_uris is missing" do
      attrs = %{client_name: "My App"}
      assert {:error, changeset} = CreateClientParams.parse(attrs)
      assert %{redirect_uris: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when redirect_uris is empty" do
      attrs = %{client_name: "My App", redirect_uris: []}
      assert {:error, changeset} = CreateClientParams.parse(attrs)
      assert %{redirect_uris: [_]} = errors_on(changeset)
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
