defmodule Supabase.GoTrue.Admin do
  @moduledoc """
  Admin module for GoTrue. This module provides functions to interact with the GoTrue admin API,
  like signing out a user, inviting a user, and generating a link.

  You can find more information about the GoTrue admin API at https://supabase.io/docs/reference/javascript/auth-admin-api
  """

  @behaviour Supabase.GoTrue.AdminBehaviour

  alias Supabase.Client
  alias Supabase.Fetcher.Response
  alias Supabase.GoTrue.AdminHandler
  alias Supabase.GoTrue.Schemas.AdminUserParams
  alias Supabase.GoTrue.Schemas.GenerateLink
  alias Supabase.GoTrue.Schemas.InviteUserParams
  alias Supabase.GoTrue.Schemas.PaginationParams
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  @scopes ~w[global local others]a

  @doc """
  Signs out a user via the admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `session` - The session to sign out, often retrieved from a sign in function.
    * `scope` - The scope to sign out the user from (atom):
      * `:global` - Sign out user from all devices and browser sessions
      * `:local` - Sign out user from current browser only
      * `:others` - Sign out user from all other devices except current browser

  ## Returns
    * `:ok` - Successfully signed out the user
    * `{:error, error}` - Failed to sign out the user

  ## Examples
      iex> session = %Session{access_token: "eyJhbGciO..."}
      iex> Supabase.GoTrue.Admin.sign_out(client, session, :global)
      :ok
  """
  @impl true
  def sign_out(%Client{} = client, %Session{} = session, scope \\ :global) when scope in @scopes do
    case AdminHandler.sign_out(client, session.access_token, scope) do
      {:ok, _} -> :ok
      {:error, %{code: :not_found}} -> :ok
      {:error, %{code: :unauthorized}} -> :ok
      err -> err
    end
  end

  @doc """
  Invites a user to join the application through email.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `email` - The email of the user to invite.
    * `options` - The options to use for the invite:
      * `data` - Additional data to include with the invitation
      * `redirect_to` - URL to redirect the user after accepting the invitation

  ## Examples
      iex> Supabase.GoTrue.Admin.invite_user_by_email(client, "john@example.com", %{redirect_to: "https://example.com/welcome"})
  """
  @impl true
  def invite_user_by_email(%Client{} = client, email, options \\ %{}) do
    with {:ok, options} <- InviteUserParams.parse(options),
         {:ok, response} <- AdminHandler.invite_user(client, email, options) do
      User.parse(response.body)
    end
  end

  @doc """
  Generates an action link for various authentication purposes.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The attributes to use for the link:
      * `email` - The email for which to generate the link (required)
      * `type` - The type of link to generate (required). One of:
        * `signup` - Sign up link (requires password)
        * `invite` - Invitation link
        * `magicLink` - Magic link for passwordless auth
        * `recovery` - Password recovery link
        * `email_change_current` - Email change confirmation for current email
        * `email_change_new` - Email change confirmation for new email
      * `password` - Required for signup links
      * `redirect_to` - URL to redirect after action is completed
      * `data` - Additional data to include

  ## Returns
  * `{:ok, properties}` - Successfully generated link with properties:
    * `action_link` - The link to send to the user
    * `email_otp` - Email OTP if applicable
    * `hashed_token` - Hashed token
    * `redirect_to` - The redirect URL
    * `verification_type` - Type of verification

  ## Examples
      iex> attrs = %{email: "user@example.com", type: "recovery", redirect_to: "https://example.com/reset-password"}
      iex> Supabase.GoTrue.Admin.generate_link(client, attrs)
      {:ok, %{action_link: "https://auth.example.com/verify?...", ...}}
  """
  @impl true
  def generate_link(%Client{} = client, attrs) do
    with {:ok, params} <- GenerateLink.parse(attrs),
         {:ok, response} <- AdminHandler.generate_link(client, params) do
      GenerateLink.properties(response.body)
    end
  end

  @doc """
  Creates a user via the admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `attrs` - The attributes to use for the user:
      * `email` - User's email address (required if phone not provided)
      * `phone` - User's phone number (required if email not provided)
      * `password` - User's password
      * `email_confirm` - Whether to mark the email as confirmed
      * `phone_confirm` - Whether to mark the phone as confirmed
      * `app_metadata` - Application-specific metadata to store with the user
      * `ban_duration` - Duration for which the user should be banned
      * `role` - User's role
      * `nonce` - Custom nonce for the user

  ## Returns
    * `{:ok, user}` - Successfully created user
    * `{:error, error}` - Failed to create user

  ## Examples
      iex> attrs = %{email: "admin-created@example.com", password: "secure-password", email_confirm: true}
      iex> Supabase.GoTrue.Admin.create_user(client, attrs)
      {:ok, %Supabase.GoTrue.User{}}
  """
  @impl true
  def create_user(%Client{} = client, attrs) do
    with {:ok, params} <- AdminUserParams.parse(attrs),
         {:ok, response} <- AdminHandler.create_user(client, params) do
      User.parse(response.body)
    end
  end

  @doc """
  Deletes a user via the admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to delete.
    * `opts` - Controls deletion behavior.
      * `should_soft_delete` - When true, the user will be soft-deleted (default: false)

  ## Returns
    * `{:ok, user}` - Successfully deleted user (returns user data)
    * `{:error, error}` - Failed to delete user

  ## Examples
      iex> Supabase.GoTrue.Admin.delete_user(client, "user_id")
      {:ok, %Supabase.GoTrue.User{}}
      
      # Soft delete a user
      iex> Supabase.GoTrue.Admin.delete_user(client, "user_id", should_soft_delete: true)
      {:ok, %Supabase.GoTrue.User{}}
  """
  @impl true
  def delete_user(%Client{} = client, user_id, opts \\ [should_soft_delete: false]) do
    with {:ok, _} <- AdminHandler.delete_user(client, user_id, opts) do
      :ok
    end
  end

  @doc """
  Gets a user by ID via the admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to get.

  ## Returns
    * `{:ok, user}` - Successfully retrieved user
    * `{:error, error}` - Failed to retrieve user

  ## Examples
      iex> Supabase.GoTrue.Admin.get_user_by_id(client, "d5bd2ef9-8df8-4e96-b592-35d120a8634c")
      {:ok, %Supabase.GoTrue.User{}}
  """
  @impl true
  def get_user_by_id(%Client{} = client, user_id) do
    with {:ok, response} <- AdminHandler.get_user(client, user_id) do
      User.parse(response.body)
    end
  end

  @doc """
  Lists users via the admin API with pagination support.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `params` - The parameters to use for the list:
      * `page` - Page number for pagination
      * `per_page` - Number of users per page

  ## Returns
    * `{:ok, users, pagination}` - Successfully retrieved users with pagination info
      * `users` - List of user objects
      * `pagination` - Pagination metadata including next_page, last_page, and total count
    * `{:error, error}` - Failed to retrieve users

  ## Examples
      iex> Supabase.GoTrue.Admin.list_users(client, %{page: 1, per_page: 10})
      {:ok, [%Supabase.GoTrue.User{}, ...], %{next_page: 2, last_page: 5, total: 42}}
  """
  @impl true
  def list_users(%Client{} = client, params \\ %{}) do
    with {:ok, params} <- PaginationParams.page_params(Map.new(params)),
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

  defp parse_next_page_count(links) do
    parse_page_count(links, ~r/.+\?page=(\d).+rel=\"next\"/)
  end

  defp parse_last_page_count(links) do
    parse_page_count(links, ~r/.+\?page=(\d).+rel=\"last\"/)
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
  Updates a user via the admin API.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user to update.
    * `attrs` - The attributes to update for the user:
      * `email` - User's email address
      * `phone` - User's phone number
      * `password` - User's password
      * `email_confirm` - Whether to mark the email as confirmed
      * `phone_confirm` - Whether to mark the phone as confirmed
      * `app_metadata` - Application-specific metadata to store with the user
      * `ban_duration` - Duration for which the user should be banned
      * `role` - User's role
      * `nonce` - Custom nonce for the user

  ## Returns
    * `{:ok, user}` - Successfully updated user
    * `{:error, error}` - Failed to update user

  ## Examples
      iex> attrs = %{role: "admin", app_metadata: %{plan: "premium"}}
      iex> Supabase.GoTrue.Admin.update_user_by_id(client, "d5bd2ef9-8df8-4e96-b592-35d120a8634c", attrs)
      {:ok, %Supabase.GoTrue.User{}}
  """
  @impl true
  def update_user_by_id(%Client{} = client, user_id, attrs) do
    with {:ok, params} <- AdminUserParams.parse_update(attrs),
         {:ok, response} <- AdminHandler.update_user(client, user_id, params) do
      User.parse(response.body)
    end
  end

  @doc """
  Deletes a multi-factor authentication factor for a user.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
    * `factor_id` - The ID of the factor to delete.
    
  ## Returns
    * `:ok` - Successfully deleted the factor
    * `{:error, error}` - Failed to delete the factor
    
  ## Examples
      iex> Supabase.GoTrue.Admin.delete_factor(client, "d5bd2ef9-8df8-4e96-b592-35d120a8634c", "totp-factor-id")
      :ok
  """
  @impl true
  def delete_factor(%Client{} = client, user_id, factor_id) do
    with {:ok, _} <- AdminHandler.delete_factor(client, user_id, factor_id), do: :ok
  end

  @doc """
  Lists all connected authentication identities for a specific user.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
    
  ## Returns
    * `{:ok, identities}` - Successfully retrieved the list of identities
    * `{:error, error}` - Failed to retrieve the identities
    
  ## Examples
      iex> Supabase.GoTrue.Admin.list_identities(client, "d5bd2ef9-8df8-4e96-b592-35d120a8634c")
      {:ok, [%Supabase.GoTrue.User.Identity{provider: :google, ...}, ...]}
  """
  @impl true
  def list_identities(%Client{} = client, user_id) do
    with {:ok, response} <- AdminHandler.list_identities(client, user_id) do
      User.Identity.parse_list(response.body)
    end
  end

  @doc """
  Removes a specific authentication identity from a user.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `user_id` - The ID of the user.
    * `identity_id` - The ID of the identity to delete.
    
  ## Returns
    * `:ok` - Successfully deleted the identity
    * `{:error, error}` - Failed to delete the identity
    
  ## Examples
      iex> Supabase.GoTrue.Admin.delete_identity(client, "d5bd2ef9-8df8-4e96-b592-35d120a8634c", "identity-id")
      :ok
  """
  @impl true
  def delete_identity(%Client{} = client, user_id, identity_id) do
    with {:ok, _} <- AdminHandler.delete_identity(client, user_id, identity_id), do: :ok
  end
end
