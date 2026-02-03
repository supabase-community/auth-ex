defmodule Supabase.Auth.Schemas.OAuth.Client do
  @moduledoc """
  Schema for OAuth client representation using schemaless changesets.

  OAuth clients represent third-party applications that can request
  authorization from users.
  """

  import Ecto.Changeset

  @type t :: %{
          id: String.t(),
          name: String.t(),
          uri: String.t(),
          logo_uri: String.t() | nil
        }

  @types %{
    id: :string,
    name: :string,
    uri: :string,
    logo_uri: :string
  }

  @doc """
  Parses OAuth client data from API response.

  Returns `{:ok, map}` with parsed client data or `{:error, changeset}` if validation fails.

  ## Examples

      iex> Client.parse(%{
      ...>   "id" => "client-123",
      ...>   "name" => "My App",
      ...>   "uri" => "https://example.com",
      ...>   "logo_uri" => "https://example.com/logo.png"
      ...> })
      {:ok, %{
        id: "client-123",
        name: "My App",
        uri: "https://example.com",
        logo_uri: "https://example.com/logo.png"
      }}

      iex> Client.parse(%{})
      {:error, %Ecto.Changeset{}}
  """
  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required([:id, :name, :uri])
    |> apply_action(:parse)
    |> case do
      {:ok, client} -> {:ok, Map.put_new(client, :logo_uri, nil)}
      error -> error
    end
  end
end
