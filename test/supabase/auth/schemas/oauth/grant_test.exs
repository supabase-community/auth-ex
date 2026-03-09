defmodule Supabase.Auth.Schemas.OAuth.GrantTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.Grant

  describe "parse/1" do
    test "successfully parses valid grant data" do
      attrs = %{
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com",
          "logo_uri" => "https://example.com/logo.png"
        },
        "scopes" => ["read", "write"],
        "granted_at" => "2024-01-01T00:00:00Z"
      }

      assert {:ok, grant} = Grant.parse(attrs)
      assert grant.scopes == ["read", "write"]
      assert grant.granted_at == "2024-01-01T00:00:00Z"
      assert grant.client.id == "client-123"
      assert grant.client.name == "My App"
      assert grant.client.uri == "https://example.com"
      assert grant.client.logo_uri == "https://example.com/logo.png"
    end

    test "successfully parses with client missing logo_uri" do
      attrs = %{
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "scopes" => ["read"],
        "granted_at" => "2024-01-01T00:00:00Z"
      }

      assert {:ok, grant} = Grant.parse(attrs)
      assert is_nil(grant.client.logo_uri)
    end

    test "returns error when scopes is missing" do
      attrs = %{
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "granted_at" => "2024-01-01T00:00:00Z"
      }

      assert {:error, changeset} = Grant.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when granted_at is missing" do
      attrs = %{
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "scopes" => ["read"]
      }

      assert {:error, changeset} = Grant.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when client is invalid" do
      attrs = %{
        "client" => %{
          "id" => "client-123"
          # missing required fields
        },
        "scopes" => ["read"],
        "granted_at" => "2024-01-01T00:00:00Z"
      }

      assert {:error, changeset} = Grant.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when client is missing" do
      attrs = %{
        "scopes" => ["read"],
        "granted_at" => "2024-01-01T00:00:00Z"
      }

      assert {:error, changeset} = Grant.parse(attrs)
      refute changeset.valid?
    end
  end

  describe "parse_list/1" do
    test "successfully parses a list of grants" do
      grants = [
        %{
          "client" => %{"id" => "c1", "name" => "App 1", "uri" => "https://app1.com"},
          "scopes" => ["read"],
          "granted_at" => "2024-01-01T00:00:00Z"
        },
        %{
          "client" => %{"id" => "c2", "name" => "App 2", "uri" => "https://app2.com"},
          "scopes" => ["write"],
          "granted_at" => "2024-01-02T00:00:00Z"
        }
      ]

      assert {:ok, parsed_grants} = Grant.parse_list(grants)
      assert length(parsed_grants) == 2
      assert Enum.at(parsed_grants, 0).client.id == "c1"
      assert Enum.at(parsed_grants, 1).client.id == "c2"
    end

    test "successfully parses an empty list" do
      assert {:ok, []} = Grant.parse_list([])
    end

    test "returns error if any grant is invalid" do
      grants = [
        %{
          "client" => %{"id" => "c1", "name" => "App 1", "uri" => "https://app1.com"},
          "scopes" => ["read"],
          "granted_at" => "2024-01-01T00:00:00Z"
        },
        %{
          "client" => %{"id" => "c2", "name" => "App 2", "uri" => "https://app2.com"}
          # missing scopes and granted_at
        }
      ]

      assert {:error, _changeset} = Grant.parse_list(grants)
    end
  end
end
