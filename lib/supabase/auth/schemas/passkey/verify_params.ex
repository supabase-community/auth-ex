defmodule Supabase.Auth.Schemas.Passkey.VerifyParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %{challenge_id: String.t(), credential: map()}

  @types %{challenge_id: :string, credential: :map}

  @spec parse(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, [:challenge_id, :credential])
    |> validate_required([:challenge_id, :credential])
    |> apply_action(:parse)
  end
end
