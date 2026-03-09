defmodule Supabase.Auth.Schemas.OAuth.Grant do
  @moduledoc """
  Schema for OAuth grant representation using schemaless changesets.

  OAuth grants represent user authorization to a third-party client application.
  """

  import Ecto.Changeset

  alias Supabase.Auth.Schemas.OAuth.Client

  @type t :: %{
          client: Client.t(),
          scopes: [String.t()],
          granted_at: String.t()
        }

  @types %{
    scopes: {:array, :string},
    granted_at: :string
  }

  @doc """
  Parses OAuth grant data from API response.

  Returns `{:ok, map}` with parsed grant data or `{:error, changeset}` if validation fails.

  ## Examples

      iex> Grant.parse(%{
      ...>   "client" => %{
      ...>     "id" => "client-123",
      ...>     "name" => "My App",
      ...>     "uri" => "https://example.com"
      ...>   },
      ...>   "scopes" => ["read", "write"],
      ...>   "granted_at" => "2024-01-01T00:00:00Z"
      ...> })
      {:ok, %{
        client: %{id: "client-123", name: "My App", uri: "https://example.com", logo_uri: nil},
        scopes: ["read", "write"],
        granted_at: "2024-01-01T00:00:00Z"
      }}

      iex> Grant.parse(%{})
      {:error, %Ecto.Changeset{}}
  """
  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    with {:ok, client} <- Client.parse(attrs["client"] || %{}) do
      {%{}, @types}
      |> cast(attrs, Map.keys(@types))
      |> validate_required([:scopes, :granted_at])
      |> apply_action(:parse)
      |> case do
        {:ok, grant} -> {:ok, Map.put(grant, :client, client)}
        error -> error
      end
    end
  end

  @doc """
  Parses a list of OAuth grants from API response.

  Returns `{:ok, [grant_map]}` with a list of parsed grants or `{:error, reason}` if any grant fails to parse.

  ## Examples

      iex> Grant.parse_list([
      ...>   %{"client" => %{"id" => "c1", "name" => "App 1", "uri" => "https://app1.com"}, "scopes" => ["read"], "granted_at" => "2024-01-01T00:00:00Z"},
      ...>   %{"client" => %{"id" => "c2", "name" => "App 2", "uri" => "https://app2.com"}, "scopes" => ["write"], "granted_at" => "2024-01-02T00:00:00Z"}
      ...> ])
      {:ok, [%{client: %{...}, scopes: ["read"], ...}, %{client: %{...}, scopes: ["write"], ...}]}
  """
  @spec parse_list([map()]) :: {:ok, [t()]} | {:error, term()}
  def parse_list(data) when is_list(data) do
    data
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case parse(item) do
        {:ok, grant} -> {:cont, {:ok, [grant | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, grants} -> {:ok, Enum.reverse(grants)}
      error -> error
    end
  end
end
