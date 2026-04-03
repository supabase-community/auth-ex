defmodule Supabase.Auth.Schemas.CustomProvider do
  @moduledoc """
  Schema for custom OAuth/OIDC provider returned from the admin API.
  """

  import Ecto.Changeset

  @provider_types ~w[oauth2 oidc]

  @type t :: %{
          id: String.t(),
          provider_type: String.t(),
          identifier: String.t(),
          name: String.t(),
          client_id: String.t(),
          acceptable_client_ids: [String.t()] | nil,
          scopes: [String.t()] | nil,
          pkce_enabled: boolean() | nil,
          attribute_mapping: map() | nil,
          authorization_params: map() | nil,
          enabled: boolean() | nil,
          email_optional: boolean() | nil,
          issuer: String.t() | nil,
          discovery_url: String.t() | nil,
          skip_nonce_check: boolean() | nil,
          authorization_url: String.t() | nil,
          token_url: String.t() | nil,
          userinfo_url: String.t() | nil,
          jwks_uri: String.t() | nil,
          discovery_document: map() | nil,
          created_at: String.t(),
          updated_at: String.t()
        }

  @types %{
    id: :string,
    provider_type: :string,
    identifier: :string,
    name: :string,
    client_id: :string,
    acceptable_client_ids: {:array, :string},
    scopes: {:array, :string},
    pkce_enabled: :boolean,
    attribute_mapping: :map,
    authorization_params: :map,
    enabled: :boolean,
    email_optional: :boolean,
    issuer: :string,
    discovery_url: :string,
    skip_nonce_check: :boolean,
    authorization_url: :string,
    token_url: :string,
    userinfo_url: :string,
    jwks_uri: :string,
    discovery_document: :map,
    created_at: :string,
    updated_at: :string
  }

  @required [:id, :provider_type, :identifier, :name, :client_id, :created_at, :updated_at]

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required(@required)
    |> validate_inclusion(:provider_type, @provider_types)
    |> apply_action(:parse)
  end

  @spec parse_list(list(map())) :: {:ok, [t()]} | {:error, term()}
  def parse_list(data) when is_list(data) do
    data
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case parse(item) do
        {:ok, provider} -> {:cont, {:ok, [provider | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, providers} -> {:ok, Enum.reverse(providers)}
      error -> error
    end
  end
end
