defmodule Supabase.Auth.Schemas.OAuth.UpdateClientParamsTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.UpdateClientParams

  describe "parse/1" do
    test "successfully parses with any subset of fields" do
      attrs = %{client_name: "Updated Name"}
      assert {:ok, params} = UpdateClientParams.parse(attrs)
      assert params.client_name == "Updated Name"
    end

    test "successfully parses with all fields" do
      attrs = %{
        client_name: "Updated Name",
        client_uri: "https://new-uri.com",
        logo_uri: "https://new-uri.com/logo.png",
        redirect_uris: ["https://new-uri.com/callback"],
        grant_types: ["authorization_code"],
        token_endpoint_auth_method: "client_secret_post"
      }

      assert {:ok, params} = UpdateClientParams.parse(attrs)
      assert params.client_name == "Updated Name"
      assert params.logo_uri == "https://new-uri.com/logo.png"
    end

    test "successfully parses empty map (no-op update)" do
      assert {:ok, _params} = UpdateClientParams.parse(%{})
    end
  end
end
