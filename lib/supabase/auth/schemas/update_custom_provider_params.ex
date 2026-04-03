defmodule Supabase.Auth.Schemas.UpdateCustomProviderParams do
  @moduledoc false

  import Ecto.Changeset

  @types %{
    name: :string,
    client_id: :string,
    client_secret: :string,
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
    jwks_uri: :string
  }

  @spec parse(map()) :: {:ok, map()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> apply_action(:parse)
  end
end
