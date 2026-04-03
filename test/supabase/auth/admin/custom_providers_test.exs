defmodule Supabase.Auth.Admin.CustomProvidersTest do
  use ExUnit.Case, async: false

  import Mox
  import Supabase.Auth.Admin.CustomProviderFixture

  alias Supabase.Auth.Admin.CustomProviders
  alias Supabase.Fetcher.Request

  @moduletag capture_log: true

  setup :verify_on_exit!

  @mock TestHTTPClient

  setup_all do
    Application.put_env(:supabase_auth, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_auth, :http_client)
    end)
  end

  setup do
    client = Supabase.init_client!("http://localhost:54321", "test-api-key")

    {:ok, client: client, json: Supabase.json_library()}
  end

  describe "list_providers/2" do
    test "successfully lists all custom providers", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/custom-providers"

        body = custom_provider_list_fixture_json()

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, providers} = CustomProviders.list_providers(client)
      assert length(providers) == 2
    end

    test "successfully filters by type", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/custom-providers"
        assert Request.get_query_param(req, "type") == "oidc"

        body = custom_provider_list_fixture_json([custom_provider_fixture()])

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, providers} = CustomProviders.list_providers(client, %{type: "oidc"})
      assert length(providers) == 1
      assert hd(providers).provider_type == "oidc"
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = CustomProviders.list_providers(client)
    end
  end

  describe "create_provider/2" do
    test "successfully creates an OIDC provider", %{client: client} do
      attrs = %{
        provider_type: "oidc",
        identifier: "custom:mycompany",
        name: "My Company SSO",
        client_id: "oauth-client-id",
        client_secret: "oauth-client-secret",
        issuer: "https://sso.mycompany.com"
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/custom-providers"

        body = custom_provider_fixture_json()

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, provider} = CustomProviders.create_provider(client, attrs)
      assert provider.identifier == "custom:mycompany"
      assert provider.provider_type == "oidc"
    end

    test "returns validation error when required fields are missing", %{client: client} do
      attrs = %{provider_type: "oidc", name: "Incomplete"}

      assert {:error, %Ecto.Changeset{}} = CustomProviders.create_provider(client, attrs)
    end

    test "returns validation error for invalid provider_type", %{client: client} do
      attrs = %{
        provider_type: "invalid",
        identifier: "custom:test",
        name: "Test",
        client_id: "id",
        client_secret: "secret"
      }

      assert {:error, %Ecto.Changeset{}} = CustomProviders.create_provider(client, attrs)
    end

    test "returns an unexpected error", %{client: client} do
      attrs = %{
        provider_type: "oidc",
        identifier: "custom:test",
        name: "Test",
        client_id: "id",
        client_secret: "secret"
      }

      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = CustomProviders.create_provider(client, attrs)
    end
  end

  describe "get_provider/2" do
    test "successfully gets a custom provider", %{client: client} do
      identifier = "custom:mycompany"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/custom-providers/#{identifier}"

        body = custom_provider_fixture_json(identifier: identifier)

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, provider} = CustomProviders.get_provider(client, identifier)
      assert provider.identifier == identifier
    end

    test "returns an error when provider doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/custom-providers/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, _} = CustomProviders.get_provider(client, "nonexistent")
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = CustomProviders.get_provider(client, "custom:test")
    end
  end

  describe "update_provider/3" do
    test "successfully updates a custom provider", %{client: client} do
      identifier = "custom:mycompany"
      attrs = %{name: "Updated Company SSO"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/custom-providers/#{identifier}"

        body = custom_provider_fixture_json(identifier: identifier, name: "Updated Company SSO")

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, provider} = CustomProviders.update_provider(client, identifier, attrs)
      assert provider.name == "Updated Company SSO"
    end

    test "returns an error when provider doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/custom-providers/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, _} = CustomProviders.update_provider(client, "nonexistent", %{name: "X"})
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} =
               CustomProviders.update_provider(client, "custom:test", %{name: "X"})
    end
  end

  describe "delete_provider/2" do
    test "successfully deletes a custom provider", %{client: client} do
      identifier = "custom:mycompany"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/custom-providers/#{identifier}"

        {:ok, %Finch.Response{body: ~s|{}|, status: 204, headers: []}}
      end)

      assert :ok = CustomProviders.delete_provider(client, identifier)
    end

    test "returns an error when provider doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/custom-providers/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = CustomProviders.delete_provider(client, "nonexistent")
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} =
               CustomProviders.delete_provider(client, "custom:test")
    end
  end
end
