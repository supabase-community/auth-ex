defmodule Supabase.GoTrue.AdminHandler do
  @moduledoc false

  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request
  alias Supabase.GoTrue
  alias Supabase.GoTrue.Schemas.InviteUserParams

  @invite "/invite"
  @generate_link "/admin/generate_link"
  @users "/admin/users"

  defp single_user_endpoint(id) do
    @users <> "/#{id}"
  end

  defp sign_out(scope) do
    "/logout?scope=#{scope}"
  end

  def sign_out(%Client{} = client, access_token, scope) do
    client
    |> GoTrue.Request.base(sign_out(scope))
    |> Request.with_method(:post)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Fetcher.request()
  end

  def invite_user(%Client{} = client, email, %InviteUserParams{} = opts) do
    body = %{email: email, data: opts.data}

    client
    |> GoTrue.Request.base(@invite)
    |> Request.with_body(body)
    |> Request.with_method(:post)
    |> Request.with_headers(%{"redirect_to" => opts.redirect_to})
    |> Fetcher.request()
  end

  def generate_link(%Client{} = client, %{type: _, redirect_to: redirect_to} = params) do
    client
    |> GoTrue.Request.base(@generate_link)
    |> Request.with_body(params)
    |> Request.with_method(:post)
    |> Request.with_headers(%{"redirect_to" => redirect_to})
    |> Fetcher.request()
  end

  def create_user(%Client{} = client, params) do
    client
    |> GoTrue.Request.base(@users)
    |> Request.with_body(params)
    |> Request.with_method(:post)
    |> Fetcher.request()
  end

  def delete_user(%Client{} = client, id, params) do
    body = %{should_soft_delete: params[:should_soft_delete] || false}
    uri = single_user_endpoint(id)

    client
    |> GoTrue.Request.base(uri)
    |> Request.with_body(body)
    |> Request.with_method(:delete)
    |> Fetcher.request()
  end

  def get_user(%Client{} = client, id) do
    uri = single_user_endpoint(id)

    client
    |> GoTrue.Request.base(uri)
    |> Fetcher.request()
  end

  def list_users(%Client{} = client, params) do
    client
    |> GoTrue.Request.base(@users)
    |> Request.with_query(%{
      "page" => to_string(Map.get(params, :page, 1)),
      "per_page" => to_string(Map.get(params, :per_page, nil))
    })
    |> Fetcher.request()
  end

  def update_user(%Client{} = client, id, params) do
    uri = single_user_endpoint(id)

    client
    |> GoTrue.Request.base(uri)
    |> Request.with_body(params)
    |> Request.with_method(:put)
    |> Fetcher.request()
  end
end
