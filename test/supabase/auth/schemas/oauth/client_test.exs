defmodule Supabase.Auth.Schemas.OAuth.ClientTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.Client

  describe "parse/1" do
    test "successfully parses valid client data with all fields" do
      attrs = %{
        "id" => "client-123",
        "name" => "My App",
        "uri" => "https://example.com",
        "logo_uri" => "https://example.com/logo.png"
      }

      assert {:ok, client} = Client.parse(attrs)
      assert client.id == "client-123"
      assert client.name == "My App"
      assert client.uri == "https://example.com"
      assert client.logo_uri == "https://example.com/logo.png"
    end

    test "successfully parses with nil logo_uri" do
      attrs = %{
        "id" => "client-123",
        "name" => "My App",
        "uri" => "https://example.com"
      }

      assert {:ok, client} = Client.parse(attrs)
      assert client.id == "client-123"
      assert client.name == "My App"
      assert client.uri == "https://example.com"
      assert is_nil(client.logo_uri)
    end

    test "returns error when id is missing" do
      attrs = %{
        "name" => "My App",
        "uri" => "https://example.com"
      }

      assert {:error, changeset} = Client.parse(attrs)
      refute changeset.valid?
      assert %{id: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when name is missing" do
      attrs = %{
        "id" => "client-123",
        "uri" => "https://example.com"
      }

      assert {:error, changeset} = Client.parse(attrs)
      refute changeset.valid?
      assert %{name: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when uri is missing" do
      attrs = %{
        "id" => "client-123",
        "name" => "My App"
      }

      assert {:error, changeset} = Client.parse(attrs)
      refute changeset.valid?
      assert %{uri: ["can't be blank"]} = errors_on(changeset)
    end

    test "returns error when required fields are missing" do
      assert {:error, changeset} = Client.parse(%{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert %{id: ["can't be blank"]} = errors
      assert %{name: ["can't be blank"]} = errors
      assert %{uri: ["can't be blank"]} = errors
    end
  end

  # Helper function to get errors from changeset
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
