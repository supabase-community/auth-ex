defmodule Supabase.Auth.Admin.OAuthTest do
  use ExUnit.Case, async: false

  import Mox
  import Supabase.Auth.Admin.OAuthClientFixture

  alias Supabase.Auth.Admin.OAuth
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

  describe "list_clients/2" do
    test "successfully lists OAuth clients without pagination", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/oauth/clients"

        body = admin_oauth_client_list_fixture_json()

        {:ok,
         %Finch.Response{
           body: body,
           status: 200,
           headers: [
             {"x-total-count", "2"},
             {"link", "</admin/oauth/clients?page=0&per_page=>; rel=\"last\""}
           ]
         }}
      end)

      assert {:ok, clients, pagination} = OAuth.list_clients(client)
      assert length(clients) == 2
      assert pagination.total == 2
      assert pagination.last_page == 0
      refute pagination[:next_page]
    end

    test "successfully lists OAuth clients with pagination", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/oauth/clients"
        assert Request.get_query_param(req, "page") == "2"
        assert Request.get_query_param(req, "per_page") == "1"

        body = admin_oauth_client_list_fixture_json([admin_oauth_client_fixture()])

        {:ok,
         %Finch.Response{
           body: body,
           status: 200,
           headers: [
             {"x-total-count", "5"},
             {"link",
              ~s(</admin/oauth/clients?page=3&per_page=1>; rel="next", </admin/oauth/clients?page=5&per_page=1>; rel="last")}
           ]
         }}
      end)

      assert {:ok, clients, pagination} = OAuth.list_clients(client, %{page: 2, per_page: 1})
      assert length(clients) == 1
      assert pagination.total == 5
      assert pagination.last_page == 5
      assert pagination.next_page == 3
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = OAuth.list_clients(client)
    end
  end

  describe "create_client/2" do
    test "successfully creates an OAuth client", %{client: client} do
      attrs = %{
        client_name: "My New App",
        redirect_uris: ["https://myapp.com/callback"]
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/oauth/clients"

        body =
          admin_oauth_client_fixture_json(
            client_name: "My New App",
            redirect_uris: ["https://myapp.com/callback"]
          )

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, oauth_client} = OAuth.create_client(client, attrs)
      assert oauth_client.client_name == "My New App"
      assert oauth_client.redirect_uris == ["https://myapp.com/callback"]
      assert oauth_client.client_secret
    end

    test "returns validation error when client_name is missing", %{client: client} do
      attrs = %{redirect_uris: ["https://myapp.com/callback"]}

      assert {:error, %Ecto.Changeset{}} = OAuth.create_client(client, attrs)
    end

    test "returns validation error when redirect_uris is missing", %{client: client} do
      attrs = %{client_name: "My App"}

      assert {:error, %Ecto.Changeset{}} = OAuth.create_client(client, attrs)
    end

    test "returns an unexpected error", %{client: client} do
      attrs = %{client_name: "My App", redirect_uris: ["https://myapp.com/callback"]}

      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = OAuth.create_client(client, attrs)
    end
  end

  describe "get_client/2" do
    test "successfully gets an OAuth client", %{client: client} do
      client_id = "client-uuid-123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/oauth/clients/#{client_id}"

        body = admin_oauth_client_fixture_json(client_id: client_id)

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, oauth_client} = OAuth.get_client(client, client_id)
      assert oauth_client.client_id == client_id
    end

    test "returns an error when client doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/oauth/clients/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, _} = OAuth.get_client(client, "nonexistent")
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = OAuth.get_client(client, "client-uuid-123")
    end
  end

  describe "update_client/3" do
    test "successfully updates an OAuth client", %{client: client} do
      client_id = "client-uuid-123"
      attrs = %{client_name: "Updated Name"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/oauth/clients/#{client_id}"

        body = admin_oauth_client_fixture_json(client_id: client_id, client_name: "Updated Name")

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, oauth_client} = OAuth.update_client(client, client_id, attrs)
      assert oauth_client.client_id == client_id
      assert oauth_client.client_name == "Updated Name"
    end

    test "returns an error when client doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/oauth/clients/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, _} = OAuth.update_client(client, "nonexistent", %{client_name: "X"})
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} =
               OAuth.update_client(client, "client-uuid-123", %{client_name: "X"})
    end
  end

  describe "delete_client/2" do
    test "successfully deletes an OAuth client", %{client: client} do
      client_id = "client-uuid-123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/oauth/clients/#{client_id}"

        {:ok, %Finch.Response{body: ~s|{}|, status: 204, headers: []}}
      end)

      assert :ok = OAuth.delete_client(client, client_id)
    end

    test "returns an error when client doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/oauth/clients/nonexistent"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = OAuth.delete_client(client, "nonexistent")
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = OAuth.delete_client(client, "client-uuid-123")
    end
  end

  describe "regenerate_client_secret/2" do
    test "successfully regenerates a client secret", %{client: client} do
      client_id = "client-uuid-123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/oauth/clients/#{client_id}/regenerate_secret"

        body =
          admin_oauth_client_fixture_json(
            client_id: client_id,
            client_secret: "new-rotated-secret"
          )

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, oauth_client} = OAuth.regenerate_client_secret(client, client_id)
      assert oauth_client.client_id == client_id
      assert oauth_client.client_secret == "new-rotated-secret"
    end

    test "returns an error when client doesn't exist", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/oauth/clients/nonexistent/regenerate_secret"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, _} = OAuth.regenerate_client_secret(client, "nonexistent")
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} =
               OAuth.regenerate_client_secret(client, "client-uuid-123")
    end
  end
end
