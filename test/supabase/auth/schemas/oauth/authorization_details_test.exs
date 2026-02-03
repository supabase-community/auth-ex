defmodule Supabase.Auth.Schemas.OAuth.AuthorizationDetailsTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.AuthorizationDetails

  describe "parse/1" do
    test "successfully parses valid authorization details without redirect_url" do
      attrs = %{
        "authorization_id" => "auth-123",
        "redirect_url" => nil,
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        },
        "scope" => "read write"
      }

      assert {:ok, details} = AuthorizationDetails.parse(attrs)
      assert details.authorization_id == "auth-123"
      assert is_nil(details.redirect_url)
      assert details.client.id == "client-123"
      assert details.user.id == "user-123"
      assert details.user.email == "user@example.com"
      assert details.scope == "read write"
    end

    test "successfully parses with redirect_url (early-exit scenario)" do
      attrs = %{
        "authorization_id" => "auth-123",
        "redirect_url" => "https://example.com/callback?code=abc123",
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        },
        "scope" => "read write"
      }

      assert {:ok, details} = AuthorizationDetails.parse(attrs)
      assert details.redirect_url == "https://example.com/callback?code=abc123"
    end

    test "returns error when authorization_id is missing" do
      attrs = %{
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        },
        "scope" => "read write"
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when scope is missing" do
      attrs = %{
        "authorization_id" => "auth-123",
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        }
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when client is invalid" do
      attrs = %{
        "authorization_id" => "auth-123",
        "client" => %{
          "id" => "client-123"
          # missing required fields
        },
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        },
        "scope" => "read write"
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when user is invalid" do
      attrs = %{
        "authorization_id" => "auth-123",
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "user" => %{
          "id" => "user-123"
          # missing email
        },
        "scope" => "read write"
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when user is missing" do
      attrs = %{
        "authorization_id" => "auth-123",
        "client" => %{
          "id" => "client-123",
          "name" => "My App",
          "uri" => "https://example.com"
        },
        "scope" => "read write"
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end

    test "returns error when client is missing" do
      attrs = %{
        "authorization_id" => "auth-123",
        "user" => %{
          "id" => "user-123",
          "email" => "user@example.com"
        },
        "scope" => "read write"
      }

      assert {:error, changeset} = AuthorizationDetails.parse(attrs)
      refute changeset.valid?
    end
  end
end
