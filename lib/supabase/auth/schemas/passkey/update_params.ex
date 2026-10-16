defmodule Supabase.Auth.Schemas.Passkey.UpdateParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @max_friendly_name_length 120

  @type t :: %{friendly_name: String.t()}

  @types %{friendly_name: :string}

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, [:friendly_name])
    |> validate_required([:friendly_name])
    |> validate_length(:friendly_name, max: @max_friendly_name_length)
    |> apply_action(:parse)
  end
end
