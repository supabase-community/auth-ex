defmodule Supabase.Auth.IdentityTest do
  use ExUnit.Case, async: false

  import Mox

  alias Supabase.Auth
  alias Supabase.Auth.Session
  alias Supabase.Auth.User
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
    {:ok, client: client}
  end

  describe "link_identity/3" do
    test "successfully gets URL to link identity", %{client: client} do
      session = %Session{access_token: "test-token"}
      provider = :github

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user/identities/authorize"
        assert Request.get_header(req, "authorization") == "Bearer test-token"

        {:ok,
         %Finch.Response{
           body: Jason.encode!(%{provider: "github", url: "https://example.com/oauth/github"}),
           status: 200,
           headers: []
         }}
      end)

      oauth_credentials = %{provider: provider, options: %{}}
      assert {:ok, result} = Auth.link_identity(client, session, oauth_credentials)
      assert result.provider == :github
      assert result.url == "https://example.com/oauth/github"
    end

    test "returns an error when not authenticated", %{client: client} do
      session = %Session{access_token: nil}
      provider = :github

      oauth_credentials = %{provider: provider, options: %{}}
      assert {:error, %Supabase.Error{}} = Auth.link_identity(client, session, oauth_credentials)
    end

    test "returns an unexpected error", %{client: client} do
      session = %Session{access_token: "test-token"}
      provider = :github

      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      oauth_credentials = %{provider: provider, options: %{}}
      assert {:error, %Supabase.Error{}} = Auth.link_identity(client, session, oauth_credentials)
    end
  end

  describe "unlink_identity/3" do
    test "successfully unlinks identity", %{client: client} do
      session = %Session{access_token: "test-token"}
      identity_id = "ident_123456789"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/user/identities/#{identity_id}"
        assert Request.get_header(req, "authorization") == "Bearer test-token"

        {:ok, %Finch.Response{body: ~s|{}|, status: 204, headers: []}}
      end)

      assert :ok = Auth.unlink_identity(client, session, identity_id)
    end

    test "returns an error when not authenticated", %{client: client} do
      session = %Session{access_token: nil}
      identity_id = "ident_123456789"

      assert {:error, %Supabase.Error{}} = Auth.unlink_identity(client, session, identity_id)
    end

    test "returns an error when trying to delete the last identity", %{client: client} do
      session = %Session{access_token: "test-token"}
      identity_id = "ident_123456789"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/user/identities/#{identity_id}"

        error_json =
          Jason.encode!(%{
            message: "Cannot delete the last identity",
            status: 400,
            code: "single_identity_not_deletable"
          })

        {:ok, %Finch.Response{body: error_json, status: 400, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.unlink_identity(client, session, identity_id)
    end

    test "returns an unexpected error", %{client: client} do
      session = %Session{access_token: "test-token"}
      identity_id = "ident_123456789"

      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.unlink_identity(client, session, identity_id)
    end
  end

  describe "get_user_identities/2" do
    test "successfully gets user identities", %{client: client} do
      session = %Session{access_token: "test-token"}

      identities_json =
        Jason.encode!([
          %{
            id: "ident_1",
            user_id: "user_123",
            identity_data: %{email: "user@github.com"},
            provider: "github",
            created_at: "2023-01-01T00:00:00Z",
            updated_at: "2023-01-01T00:00:00Z"
          },
          %{
            id: "ident_2",
            user_id: "user_123",
            identity_data: %{email: "user@google.com"},
            provider: "google",
            created_at: "2023-01-01T00:00:00Z",
            updated_at: "2023-01-01T00:00:00Z"
          }
        ])

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user/identities"
        assert Request.get_header(req, "authorization") == "Bearer test-token"

        {:ok, %Finch.Response{body: identities_json, status: 200, headers: []}}
      end)

      assert {:ok, identities} = Auth.get_user_identities(client, session)
      assert length(identities) == 2
      assert Enum.all?(identities, fn identity -> is_struct(identity, User.Identity) end)
      # Instead of relying on exact order, check that both providers exist
      assert Enum.any?(identities, fn identity -> identity.provider == :github end)
      assert Enum.any?(identities, fn identity -> identity.provider == :google end)
    end

    test "returns an error when not authenticated", %{client: client} do
      session = %Session{access_token: nil}
      assert {:error, %Supabase.Error{}} = Auth.get_user_identities(client, session)
    end

    test "returns an unexpected error", %{client: client} do
      session = %Session{access_token: "test-token"}

      expect(@mock, :request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.get_user_identities(client, session)
    end
  end
end
