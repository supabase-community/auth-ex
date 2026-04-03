defmodule Supabase.Auth.Admin.OAuthHandler do
  @moduledoc false

  alias Supabase.Auth
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request

  @clients_uri "/admin/oauth/clients"

  defp client_uri(client_id) do
    @clients_uri <> "/#{client_id}"
  end

  defp regenerate_secret_uri(client_id) do
    client_uri(client_id) <> "/regenerate_secret"
  end

  def list_clients(%Client{} = client, params) do
    client
    |> Auth.Request.base(@clients_uri)
    |> Request.with_method(:get)
    |> Request.with_query(%{
      "page" => to_string(Map.get(params, :page, 1)),
      "per_page" => to_string(Map.get(params, :per_page, ""))
    })
    |> Fetcher.request()
  end

  def create_client(%Client{} = client, params) do
    client
    |> Auth.Request.base(@clients_uri)
    |> Request.with_method(:post)
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  def get_client(%Client{} = client, client_id) do
    client
    |> Auth.Request.base(client_uri(client_id))
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  def update_client(%Client{} = client, client_id, params) do
    client
    |> Auth.Request.base(client_uri(client_id))
    |> Request.with_method(:put)
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  def delete_client(%Client{} = client, client_id) do
    client
    |> Auth.Request.base(client_uri(client_id))
    |> Request.with_method(:delete)
    |> Fetcher.request()
  end

  def regenerate_client_secret(%Client{} = client, client_id) do
    client
    |> Auth.Request.base(regenerate_secret_uri(client_id))
    |> Request.with_method(:post)
    |> Fetcher.request()
  end
end
