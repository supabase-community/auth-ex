defmodule Supabase.Auth.Admin.CustomProvidersHandler do
  @moduledoc false

  alias Supabase.Auth
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request

  @base_uri "/admin/custom-providers"

  defp provider_uri(identifier) do
    @base_uri <> "/#{identifier}"
  end

  def list_providers(%Client{} = client, params) do
    query =
      case Map.get(params, :type) do
        nil -> %{}
        type -> %{"type" => to_string(type)}
      end

    client
    |> Auth.Request.base(@base_uri)
    |> Request.with_method(:get)
    |> Request.with_query(query)
    |> Fetcher.request()
  end

  def create_provider(%Client{} = client, params) do
    client
    |> Auth.Request.base(@base_uri)
    |> Request.with_method(:post)
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  def get_provider(%Client{} = client, identifier) do
    client
    |> Auth.Request.base(provider_uri(identifier))
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  def update_provider(%Client{} = client, identifier, params) do
    client
    |> Auth.Request.base(provider_uri(identifier))
    |> Request.with_method(:put)
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  def delete_provider(%Client{} = client, identifier) do
    client
    |> Auth.Request.base(provider_uri(identifier))
    |> Request.with_method(:delete)
    |> Fetcher.request()
  end
end
