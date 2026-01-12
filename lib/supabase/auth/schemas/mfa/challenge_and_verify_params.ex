defmodule Supabase.Auth.Schemas.MFA.ChallengeAndVerifyParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %{code: String.t()}

  @types %{code: :string}

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(%{code: _} = attrs) do
    {%{}, @types}
    |> cast(attrs, [:code])
    |> validate_required([:code])
    |> validate_length(:code, is: 6)
    |> apply_action(:parse)
  end
end
