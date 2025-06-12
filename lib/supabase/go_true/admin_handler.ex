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

  defp factors_endpoint(user_id) do
    @users <> "/#{user_id}/factors"
  end

  defp factor_endpoint(user_id, factor_id) do
    factors_endpoint(user_id) <> "/#{factor_id}"
  end

  defp identities_endpoint(user_id) do
    @users <> "/#{user_id}/identities"
  end

  defp identity_endpoint(user_id, identity_id) do
    identities_endpoint(user_id) <> "/#{identity_id}"
  end

  defp sign_out(scope) do
    "/logout?scope=#{scope}"
  end

  def sign_out(%Client{} = client, access_token, scope) do
    client
    |> GoTrue.Request.base(sign_out(scope))
    |> Request.with_body_decoder(GoTrue.Request.JSONDecoder)
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

  @doc """
  Deletes a user's MFA factor.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
    * `factor_id` - The ID of the factor to delete.
  """
  def delete_factor(%Client{} = client, user_id, factor_id) do
    uri = factor_endpoint(user_id, factor_id)

    client
    |> GoTrue.Request.base(uri)
    |> Request.with_method(:delete)
    |> Fetcher.request()
  end

  @doc """
  Lists all identities for a specific user.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
  """
  def list_identities(%Client{} = client, user_id) do
    uri = identities_endpoint(user_id)

    client
    |> GoTrue.Request.base(uri)
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  @doc """
  Deletes a specific identity from a user.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
    * `identity_id` - The ID of the identity to delete.
  """
  def delete_identity(%Client{} = client, user_id, identity_id) do
    uri = identity_endpoint(user_id, identity_id)

    client
    |> GoTrue.Request.base(uri)
    |> Request.with_method(:delete)
    |> Fetcher.request()
  end
end
