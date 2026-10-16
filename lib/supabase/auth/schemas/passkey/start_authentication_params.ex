defmodule Supabase.Auth.Schemas.Passkey.StartAuthenticationParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %{captcha_token: String.t() | nil}

  @types %{captcha_token: :string}

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, [:captcha_token])
    |> apply_action(:parse)
  end

  @doc """
  Builds the wire body. Mirrors auth-js exactly: the `gotrue_meta_security`
  wrapper is always sent; `captcha_token` is present only when set (auth-js
  serializes an absent token as an empty object).
  """
  @spec to_request(map()) ::
          {:ok, %{gotrue_meta_security: %{optional(:captcha_token) => String.t()}}}
          | {:error, Ecto.Changeset.t()}
  def to_request(attrs) do
    with {:ok, data} <- parse(attrs) do
      security = if Map.get(data, :captcha_token), do: %{captcha_token: Map.get(data, :captcha_token)}, else: %{}
      {:ok, %{gotrue_meta_security: security}}
    end
  end
end
