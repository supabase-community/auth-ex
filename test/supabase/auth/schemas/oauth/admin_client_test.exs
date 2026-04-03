defmodule Supabase.Auth.Schemas.OAuth.AdminClientTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.AdminClient

  @valid_attrs %{
    "client_id" => "client-123",
    "client_name" => "My App",
    "client_type" => "confidential",
    "token_endpoint_auth_method" => "client_secret_basic",
    "registration_type" => "manual",
    "redirect_uris" => ["https://example.com/callback"],
    "grant_types" => ["authorization_code", "refresh_token"],
    "response_types" => ["code"],
    "created_at" => "2024-01-01T00:00:00Z",
    "updated_at" => "2024-01-01T00:00:00Z"
  }

  describe "parse/1" do
    test "successfully parses valid admin client data" do
      attrs =
        Map.merge(@valid_attrs, %{
          "client_secret" => "secret-abc",
          "client_uri" => "https://example.com",
          "logo_uri" => "https://example.com/logo.png",
          "scope" => "openid profile"
        })

      assert {:ok, client} = AdminClient.parse(attrs)
      assert client.client_id == "client-123"
      assert client.client_name == "My App"
      assert client.client_secret == "secret-abc"
      assert client.client_type == "confidential"
      assert client.redirect_uris == ["https://example.com/callback"]
      assert client.grant_types == ["authorization_code", "refresh_token"]
    end

    test "successfully parses with only required fields" do
      assert {:ok, client} = AdminClient.parse(@valid_attrs)
      assert client.client_id == "client-123"
      refute Map.has_key?(client, :client_secret)
      refute Map.has_key?(client, :client_uri)
      refute Map.has_key?(client, :logo_uri)
      refute Map.has_key?(client, :scope)
    end

    test "returns error when client_id is missing" do
      attrs = Map.delete(@valid_attrs, "client_id")
      assert {:error, changeset} = AdminClient.parse(attrs)
      assert %{client_id: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when client_name is missing" do
      attrs = Map.delete(@valid_attrs, "client_name")
      assert {:error, changeset} = AdminClient.parse(attrs)
      assert %{client_name: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error for invalid client_type" do
      attrs = Map.put(@valid_attrs, "client_type", "invalid")
      assert {:error, changeset} = AdminClient.parse(attrs)
      assert %{client_type: [_]} = errors_on(changeset)
    end

    test "returns error for invalid grant_types" do
      attrs = Map.put(@valid_attrs, "grant_types", ["invalid_grant"])
      assert {:error, changeset} = AdminClient.parse(attrs)
      assert %{grant_types: [_]} = errors_on(changeset)
    end

    test "returns error when all required fields are missing" do
      assert {:error, changeset} = AdminClient.parse(%{})
      errors = errors_on(changeset)
      assert errors[:client_id]
      assert errors[:client_name]
      assert errors[:client_type]
      assert errors[:redirect_uris]
      assert errors[:grant_types]
      assert errors[:response_types]
      assert errors[:created_at]
      assert errors[:updated_at]
    end
  end

  describe "parse_list/1" do
    test "successfully parses a list of clients" do
      data = [
        @valid_attrs,
        Map.merge(@valid_attrs, %{"client_id" => "client-456", "client_name" => "Other App"})
      ]

      assert {:ok, clients} = AdminClient.parse_list(data)
      assert length(clients) == 2
      assert Enum.at(clients, 0).client_id == "client-123"
      assert Enum.at(clients, 1).client_id == "client-456"
    end

    test "returns error if any client in list is invalid" do
      data = [@valid_attrs, %{}]

      assert {:error, _} = AdminClient.parse_list(data)
    end

    test "successfully parses empty list" do
      assert {:ok, []} = AdminClient.parse_list([])
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
