defmodule Supabase.Auth.Schemas.OAuth.AuthorizationDetails do
  @moduledoc """
  Schema for OAuth authorization request details using schemaless changesets.

  Contains information about an OAuth authorization request, including
  the requesting client, user, and requested scopes.

  ## Early-Exit Scenario

  If the `redirect_url` field is present, the user has already consented
  to this authorization request and should be redirected immediately without
  showing a consent screen.

  ## Examples

      # User needs to provide consent
      %{
        authorization_id: "auth-123",
        redirect_url: nil,
        client: %{id: "client-123", name: "My App", ...},
        user: %{id: "user-123", email: "user@example.com"},
        scope: "read write"
      }

      # User already consented (early-exit)
      %{
        authorization_id: "auth-123",
        redirect_url: "https://app.com/callback?code=...",
        client: %{...},
        user: %{...},
        scope: "read write"
      }
  """

  import Ecto.Changeset

  alias Supabase.Auth.Schemas.OAuth.Client

  @type t :: %{
          authorization_id: String.t(),
          redirect_url: String.t() | nil,
          client: Client.t(),
          user: %{id: String.t(), email: String.t()},
          scope: String.t()
        }

  @types %{
    authorization_id: :string,
    redirect_url: :string,
    scope: :string
  }

  @user_types %{
    id: :string,
    email: :string
  }

  @doc """
  Parses OAuth authorization details from API response.

  Returns `{:ok, map}` with parsed authorization details or `{:error, changeset}` if validation fails.

  ## Examples

      iex> AuthorizationDetails.parse(%{
      ...>   "authorization_id" => "auth-123",
      ...>   "redirect_url" => nil,
      ...>   "client" => %{"id" => "c1", "name" => "App", "uri" => "https://app.com"},
      ...>   "user" => %{"id" => "u1", "email" => "user@example.com"},
      ...>   "scope" => "read write"
      ...> })
      {:ok, %{
        authorization_id: "auth-123",
        redirect_url: nil,
        client: %{id: "c1", name: "App", uri: "https://app.com", logo_uri: nil},
        user: %{id: "u1", email: "user@example.com"},
        scope: "read write"
      }}
  """
  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    with {:ok, client} <- Client.parse(attrs["client"] || %{}),
         {:ok, user} <- parse_user(attrs["user"] || %{}) do
      {%{}, @types}
      |> cast(attrs, Map.keys(@types))
      |> validate_required([:authorization_id, :scope])
      |> apply_action(:parse)
      |> case do
        {:ok, details} ->
          {:ok,
           details
           |> Map.put(:client, client)
           |> Map.put(:user, user)
           |> Map.put_new(:redirect_url, nil)}

        error ->
          error
      end
    end
  end

  @spec parse_user(map()) :: {:ok, %{id: String.t(), email: String.t()}} | {:error, Ecto.Changeset.t()}
  defp parse_user(user_data) do
    {%{}, @user_types}
    |> cast(user_data, Map.keys(@user_types))
    |> validate_required([:id, :email])
    |> apply_action(:parse)
  end
end
