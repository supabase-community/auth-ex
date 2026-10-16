defmodule Supabase.Auth.JWKS do
  @jwks_ttl 600
  @moduledoc """
  Fetches and caches the JSON Web Key Set (JWKS) from the Auth server's
  `/.well-known/jwks.json` endpoint, for local verification of
  asymmetrically-signed JWTs by `Supabase.Auth.get_claims/3`.

  Keys are cached per project (the client's auth URL) in `:persistent_term`
  under a single fixed key, with a TTL of #{@jwks_ttl} seconds, mirroring
  auth-js's in-memory JWKS cache (`JWKS_TTL` = 10 minutes).

  Concurrency: two processes refreshing concurrently may lose one cache
  write (the whole cache map is rewritten last-write-wins). The loser's next
  `fetch/2` simply refetches. Never holds up verification correctness.
  """

  alias Supabase.Auth.Request, as: AuthRequest
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request
  alias Supabase.Fetcher.Response

  @cache_key {__MODULE__, :cache}

  @type jwk :: map()
  @type entry :: %{keys: [jwk()], cached_at: integer()}

  @doc """
  Returns the JWKS for `client`'s project, from cache when fresh.

  Cache rules: an entry is fresh while `cached_at + #{@jwks_ttl} > now`
  (wall clock, `System.os_time(:second)`, mirroring auth-js `Date.now()`).
  A missing, stale, or empty-keyed entry triggers one HTTP fetch. Only a
  successful non-empty fetch is cached. Empty key lists and malformed
  bodies return exactly what the previous inline implementation returned
  (`{:ok, []}` / `{:error, :invalid_jwks_response}`) without caching.

  Pass `force: true` to bypass the cache and refetch from the server.
  """
  @spec fetch(Client.t(), opts) :: {:ok, [jwk()]} | {:error, term()} when opts: [force: boolean()]
  def fetch(%Client{} = client, opts \\ []) do
    if Keyword.get(opts, :force, false) or stale?(get_cached(client)) do
      refresh(client)
    else
      {:ok, Map.fetch!(get_cached(client), :keys)}
    end
  end

  @doc """
  Seeds the cache for `client`'s project. Primary use is testing
  (e.g. backdating entries via `cached_at:`) and warming the cache at boot.
  """
  @spec put(Client.t(), [jwk()], opts) :: :ok when opts: [cached_at: integer()]
  def put(%Client{} = client, keys, opts \\ []) when is_list(keys) do
    entry = %{keys: keys, cached_at: Keyword.get(opts, :cached_at, System.os_time(:second))}
    cache = Map.put(:persistent_term.get(@cache_key, %{}), client.auth_url, entry)
    :persistent_term.put(@cache_key, cache)
    :ok
  end

  @doc "Clears every cached JWKS. Test seam; also safe to call at runtime."
  @spec reset() :: :ok
  def reset do
    :persistent_term.put(@cache_key, %{})
    :ok
  end

  defp get_cached(%Client{} = client) do
    :persistent_term.get(@cache_key, %{})[client.auth_url]
  end

  defp stale?(nil), do: true

  defp stale?(%{cached_at: cached_at}) do
    System.os_time(:second) - cached_at >= @jwks_ttl
  end

  defp refresh(%Client{} = client) do
    case request_jwks(client) do
      {:ok, %Response{body: %{"keys" => keys}}} when is_list(keys) and keys != [] ->
        put(client, keys)
        {:ok, keys}

      {:ok, %Response{body: %{"keys" => []}}} ->
        {:ok, []}

      {:ok, _other_body} ->
        {:error, :invalid_jwks_response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp request_jwks(%Client{} = client) do
    client
    |> AuthRequest.base("/.well-known/jwks.json")
    |> Request.with_method(:get)
    |> Fetcher.request()
  end
end
