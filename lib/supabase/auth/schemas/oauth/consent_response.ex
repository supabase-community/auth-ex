defmodule Supabase.Auth.Schemas.OAuth.ConsentResponse do
  @moduledoc """
  Schema for OAuth consent response using schemaless changesets.

  Contains the redirect URL to continue the OAuth flow after
  the user approves or denies the authorization request.

  ## Examples

      %{
        redirect_url: "https://app.com/callback?code=abc123..."
      }
  """

  import Ecto.Changeset

  @type t :: %{
          redirect_url: String.t()
        }

  @types %{
    redirect_url: :string
  }

  @doc """
  Parses OAuth consent response from API response.

  Returns `{:ok, map}` with parsed consent response or `{:error, changeset}` if validation fails.

  ## Examples

      iex> ConsentResponse.parse(%{
      ...>   "redirect_url" => "https://app.com/callback?code=abc123"
      ...> })
      {:ok, %{redirect_url: "https://app.com/callback?code=abc123"}}

      iex> ConsentResponse.parse(%{})
      {:error, %Ecto.Changeset{}}
  """
  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required([:redirect_url])
    |> apply_action(:parse)
  end
end
