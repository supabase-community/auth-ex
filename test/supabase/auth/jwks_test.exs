defmodule Supabase.Auth.JWKSTest do
  # async: false: the http_client mock is set as global application env in
  # setup_all; async modules tear it down when they finish, which races with
  # other async modules still running in the full suite
  use ExUnit.Case, async: false

  import Mox
  import Supabase.Auth.JWTFixture

  alias Supabase.Auth.JWKS
  alias Supabase.Fetcher.Request

  @moduletag capture_log: true

  @mock TestHTTPClient

  setup :verify_on_exit!

  setup_all do
    Application.put_env(:supabase_auth, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_auth, :http_client)
    end)
  end

  setup do
    # the cache is keyed by the client's auth URL in :persistent_term
    # (BEAM-global), so every test gets a unique project URL and clears
    # the cache afterwards to keep async tests isolated
    client = Supabase.init_client!("http://localhost:#{System.unique_integer([:positive])}", "test-api-key")

    on_exit(fn -> JWKS.reset() end)

    {:ok, client: client, json: Supabase.json_library()}
  end

  describe "fetch/2" do
    test "fetches from the server and caches", %{client: client, json: json} do
      {_jwt, jwk} = rs256_jwt(%{}, "cache-key-id")
      jwks = jwks_from_jwk(jwk, "cache-key-id")

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/.well-known/jwks.json"

        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      assert {:ok, keys} = JWKS.fetch(client)
      assert keys == jwks["keys"]

      # cached: no additional expectation, so any HTTP call would fail
      assert {:ok, ^keys} = JWKS.fetch(client)
    end

    test "force refetches a fresh cache", %{client: client, json: json} do
      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/.well-known/jwks.json"

        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      assert {:ok, _keys} = JWKS.fetch(client)
      assert {:ok, _keys} = JWKS.fetch(client, force: true)
    end

    test "refetches when the entry is stale", %{client: client, json: json} do
      {_jwt, jwk} = rs256_jwt(%{}, "stale-key-id")
      jwks = jwks_from_jwk(jwk, "stale-key-id")

      JWKS.put(client, jwks["keys"], cached_at: System.os_time(:second) - 601)

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/.well-known/jwks.json"

        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      assert {:ok, keys} = JWKS.fetch(client)
      assert keys == jwks["keys"]
    end

    test "serves a fresh seeded cache without HTTP", %{client: client} do
      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      JWKS.put(client, jwks["keys"])

      # no expectation: a fresh entry must be served from the cache
      assert {:ok, keys} = JWKS.fetch(client)
      assert keys == jwks["keys"]
    end

    test "does not cache failures", %{client: client, json: json} do
      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 500, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = JWKS.fetch(client)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      assert {:ok, keys} = JWKS.fetch(client)
      assert keys == jwks["keys"]
    end

    test "returns error for malformed body, uncached", %{client: client, json: json} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(%{"foo" => 1}), headers: []}}
      end)

      assert {:error, :invalid_jwks_response} = JWKS.fetch(client)

      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      # nothing was cached, so the second fetch consumes a new expectation
      assert {:ok, _keys} = JWKS.fetch(client)
    end

    test "returns and does not cache an empty key set", %{client: client, json: json} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(%{"keys" => []}), headers: []}}
      end)

      assert {:ok, []} = JWKS.fetch(client)

      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      # nothing was cached, so the second fetch consumes a new expectation
      assert {:ok, _keys} = JWKS.fetch(client)
    end

    test "isolates caches per project", %{json: json} do
      client_a = Supabase.init_client!("http://localhost:#{System.unique_integer([:positive])}", "test-api-key")
      client_b = Supabase.init_client!("http://localhost:#{System.unique_integer([:positive])}", "test-api-key")

      {_jwt, jwk_a} = rs256_jwt(%{}, "project-a-key")
      jwks_a = jwks_from_jwk(jwk_a, "project-a-key")
      {_jwt, jwk_b} = rs256_jwt(%{}, "project-b-key")
      jwks_b = jwks_from_jwk(jwk_b, "project-b-key")

      expect(@mock, :request, 2, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/.well-known/jwks.json"

        body =
          if req.url.port == URI.parse(client_a.auth_url).port do
            json.encode!(jwks_a)
          else
            json.encode!(jwks_b)
          end

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, keys_a} = JWKS.fetch(client_a)
      assert {:ok, keys_b} = JWKS.fetch(client_b)
      assert keys_a == jwks_a["keys"]
      assert keys_b == jwks_b["keys"]
      refute keys_a == keys_b
    end

    test "reset clears all entries", %{client: client, json: json} do
      {_jwt, jwk} = rs256_jwt()
      jwks = jwks_from_jwk(jwk)

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      assert {:ok, _keys} = JWKS.fetch(client)

      JWKS.reset()

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 200, body: json.encode!(jwks), headers: []}}
      end)

      # the entry was cleared, so this fetch consumes a new expectation
      assert {:ok, _keys} = JWKS.fetch(client)
    end
  end
end
