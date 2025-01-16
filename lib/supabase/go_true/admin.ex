defmodule Supabase.GoTrue.Admin do
  @moduledoc """
  Admin module for GoTrue. This module provides functions to interact with the GoTrue admin API,
  like signing out a user, inviting a user, and generating a link.

  You can find more information about the GoTrue admin API at https://supabase.io/docs/reference/javascript/auth-admin-api
  """

  alias Supabase.Client
  alias Supabase.Fetcher.Response
  alias Supabase.GoTrue.AdminHandler
  alias Supabase.GoTrue.Schemas.AdminUserParams
  alias Supabase.GoTrue.Schemas.GenerateLink
  alias Supabase.GoTrue.Schemas.InviteUserParams
  alias Supabase.GoTrue.Schemas.PaginationParams
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  @behaviour Supabase.GoTrue.AdminBehaviour

  @scopes ~w[global local others]a

  @doc """
  Signs out a user from the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `session` - The session to sign out, often retrieved from a sign in function.
    * `scope` - The scope to sign out the user from. Can be one of `global`, `local`, or `others`.

  ## Examples
      iex> session = %Session{access_token: "access_token"}
      iex> Supabase.GoTrue.Admin.sign_out(pid | client_name, session, "global")
  """
  @impl true
  def sign_out(%Client{} = client, %Session{} = session, scope) when scope in @scopes do
      case AdminHandler.sign_out(client, session.access_token, scope) do
        {:ok, _} -> :ok
        {:error, %{code: :not_found}} -> :ok
        {:error, %{code: :unauthorized}} -> :ok
        err -> err
      end
  end

  @doc """
  Invites a user to the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `email` - The email of the user to invite.
    * `options` - The options to use for the invite. See `Supabase.GoTrue.Schemas.InviteUserParams` for more information.

  ## Examples
      iex> Supabase.GoTrue.Admin.invite_user_by_email(pid | client_name, "john@example.com", %{})
  """
  @impl true
  def invite_user_by_email(%Client{} = client, email, options \\ %{}) do
    with {:ok, options} <- InviteUserParams.parse(options),
         {:ok, response} <- AdminHandler.invite_user(client, email, options) do
      User.parse(response.body)
    end
  end

  @doc """
  Generates a link for the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The attributes to use for the link. See `Supabase.GoTrue.Schemas.GenerateLink` for more information.

  ## Examples
      iex> Supabase.GoTrue.Admin.generate_link(pid | client_name, %{})
  """
  @impl true
  def generate_link(%Client{} = client, attrs) do
    with {:ok, params} <- GenerateLink.parse(attrs),
         {:ok, response} <- AdminHandler.generate_link(client, params) do
      GenerateLink.properties(response.body)
    end
  end

  @doc """
  Creates a user in the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The attributes to use for the user. See `Supabase.GoTrue.Schemas.AdminUserParams` for more information.

  ## Examples
      iex> Supabase.GoTrue.Admin.create_user(pid | client_name, %{})
  """
  @impl true
  def create_user(%Client{} = client, attrs) do
    with {:ok, params} <- AdminUserParams.parse(attrs),
         {:ok, response} <- AdminHandler.create_user(client, params) do
      User.parse(response.body)
    end
  end

  @doc """
  Deletes a user in the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to delete.
    * `opts` - Controls if the user should be soft deleted or not.

  ## Examples
      iex> Supabase.GoTrue.Admin.update_user(pid | client_name, "user_id", %{})
  """
  @impl true
  def delete_user(%Client{} = client, user_id, opts \\ [should_soft_delete: false]) do
    with {:ok, _} <- AdminHandler.delete_user(client, user_id, opts) do
      :ok
    end
  end

  @doc """
  Gets a user by ID in the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to get.

  ## Examples
      iex> Supabase.GoTrue.Admin.get_user_by_id(pid | client_name, "user_id")
  """
  @impl true
  def get_user_by_id(%Client{} = client, user_id) do
    with {:ok, response} <- AdminHandler.get_user(client, user_id) do
      User.parse(response.body)
    end
  end

  @doc """
  Lists users in the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `params` - The parameters to use for the list. See `Supabase.GoTrue.Schemas.PaginationParams` for more information.

  ## Examples
      iex> Supabase.GoTrue.Admin.list_users(pid | client_name, %{})
  """
  @impl true
  def list_users(%Client{} = client, params \\ %{}) do
    with {:ok, params} <- PaginationParams.page_params(params),
         {:ok, response} <- AdminHandler.list_users(client, params),
         {:ok, users} <- User.parse_list(response.body["users"]) do
      total = Response.get_header(response, "x-total-count")

      links =
        response
        |> Response.get_header("link", "")
        |> String.split(",", trim: true)

      next = parse_next_page_count(links)
      last = parse_last_page_count(links)

      attrs = %{next_page: (next != 0 && next) || nil, last_page: last, total: total}
      {:ok, pagination} = PaginationParams.pagination(attrs)

      {:ok, users, pagination}
    end
  end

  @next_page_rg ~r/.+\?page=(\d).+rel=\"next\"/
  @last_page_rg ~r/.+\?page=(\d).+rel=\"last\"/

  defp parse_next_page_count(links) do
    parse_page_count(links, @next_page_rg)
  end

  defp parse_last_page_count(links) do
    parse_page_count(links, @last_page_rg)
  end

  defp parse_page_count(links, regex) do
    Enum.reduce_while(links, 0, fn link, acc ->
      case Regex.run(regex, link) do
        [_, page] -> {:halt, page}
        _ -> {:cont, acc}
      end
    end)
  end

  @doc """
  Updates a user in the GoTrue admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to update.
    * `attrs` - The attributes to use for the user. See `Supabase.GoTrue.Schemas.AdminUserParams` for more information.

  ## Examples
      iex> Supabase.GoTrue.Admin.update_user(pid | client_name, "user_id", %{})
  """
  @impl true
  def update_user_by_id(%Client{} = client, user_id, attrs) do
    with {:ok, params} <- AdminUserParams.parse_update(attrs),
         {:ok, response} <- AdminHandler.update_user(client, user_id, params) do
      User.parse(response.body)
    end
  end
end
