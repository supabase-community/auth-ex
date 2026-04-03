defmodule Supabase.Auth.Schemas.OAuth.CreateClientParams do
  @moduledoc false

  import Ecto.Changeset

  @types %{
    client_name: :string,
    client_uri: :string,
    redirect_uris: {:array, :string},
    grant_types: {:array, :string},
    response_types: {:array, :string},
    scope: :string,
    token_endpoint_auth_method: :string
  }

  @spec parse(map()) :: {:ok, map()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required([:client_name, :redirect_uris])
    |> validate_length(:redirect_uris, min: 1)
    |> apply_action(:parse)
  end
end
