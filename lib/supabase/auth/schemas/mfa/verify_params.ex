defmodule Supabase.Auth.Schemas.MFA.VerifyParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type code_params :: %{code: String.t()}
  @type webauthn_params :: %{webauthn: map()}
  @type t :: code_params | webauthn_params

  @code_types %{code: :string}
  @webauthn_types %{webauthn: :map}

  @spec parse(code_params) :: {:ok, code_params} | {:error, Ecto.Changeset.t()}
  @spec parse(webauthn_params) :: {:ok, webauthn_params} | {:error, Ecto.Changeset.t()}
  def parse(%{code: _} = attrs) do
    {%{}, @code_types}
    |> cast(attrs, [:code])
    |> validate_required([:code])
    |> validate_length(:code, is: 6)
    |> apply_action(:parse)
  end

  def parse(%{webauthn: _} = attrs) do
    {%{}, @webauthn_types}
    |> cast(attrs, [:webauthn])
    |> validate_required([:webauthn])
    |> apply_action(:parse)
  end
end
