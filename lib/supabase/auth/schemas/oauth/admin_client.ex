defmodule Supabase.Auth.Schemas.OAuth.AdminClient do
  @moduledoc """
  Schema for OAuth client representation in admin operations.

  Admin OAuth clients contain the full client configuration as returned
  by the GoTrue admin API, including secrets, redirect URIs, grant types,
  and authentication methods.
  """

  import Ecto.Changeset

  @client_types ~w[public confidential]
  @registration_types ~w[dynamic manual]
  @token_endpoint_auth_methods ~w[none client_secret_basic client_secret_post]
  @grant_types ~w[authorization_code refresh_token]
  @response_types ~w[code]

  @type t :: %{
          client_id: String.t(),
          client_name: String.t(),
          client_secret: String.t() | nil,
          client_type: String.t(),
          token_endpoint_auth_method: String.t(),
          registration_type: String.t(),
          client_uri: String.t() | nil,
          logo_uri: String.t() | nil,
          redirect_uris: [String.t()],
          grant_types: [String.t()],
          response_types: [String.t()],
          scope: String.t() | nil,
          created_at: String.t(),
          updated_at: String.t()
        }

  @types %{
    client_id: :string,
    client_name: :string,
    client_secret: :string,
    client_type: :string,
    token_endpoint_auth_method: :string,
    registration_type: :string,
    client_uri: :string,
    logo_uri: :string,
    redirect_uris: {:array, :string},
    grant_types: {:array, :string},
    response_types: {:array, :string},
    scope: :string,
    created_at: :string,
    updated_at: :string
  }

  @required [
    :client_id,
    :client_name,
    :client_type,
    :redirect_uris,
    :grant_types,
    :response_types,
    :created_at,
    :updated_at
  ]

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required(@required)
    |> validate_inclusion(:client_type, @client_types)
    |> validate_inclusion(:registration_type, @registration_types)
    |> validate_inclusion(:token_endpoint_auth_method, @token_endpoint_auth_methods)
    |> validate_subset(:grant_types, @grant_types)
    |> validate_subset(:response_types, @response_types)
    |> apply_action(:parse)
  end

  @spec parse_list(list(map())) :: {:ok, [t()]} | {:error, term()}
  def parse_list(data) when is_list(data) do
    data
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case parse(item) do
        {:ok, client} -> {:cont, {:ok, [client | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, clients} -> {:ok, Enum.reverse(clients)}
      error -> error
    end
  end
end
