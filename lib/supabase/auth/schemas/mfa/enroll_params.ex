defmodule Supabase.Auth.Schemas.MFA.EnrollParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type totp :: %{
          factor_type: :totp,
          friendly_name: String.t() | nil,
          issuer: String.t() | nil
        }

  @type phone :: %{
          factor_type: :phone,
          friendly_name: String.t() | nil,
          phone: String.t()
        }

  @type webauthn :: %{
          factor_type: :webauthn,
          friendly_name: String.t() | nil
        }

  @type t :: totp | phone | webauthn

  @factor_types [:totp, :phone, :webauthn]

  @totp_types %{
    factor_type: Ecto.ParameterizedType.init(Ecto.Enum, values: @factor_types),
    friendly_name: :string,
    issuer: :string
  }

  @phone_types %{
    factor_type: Ecto.ParameterizedType.init(Ecto.Enum, values: @factor_types),
    friendly_name: :string,
    phone: :string
  }

  @webauthn_types %{
    factor_type: Ecto.ParameterizedType.init(Ecto.Enum, values: @factor_types),
    friendly_name: :string
  }

  @spec parse(totp) :: {:ok, totp} | {:error, Ecto.Changeset.t()}
  @spec parse(phone) :: {:ok, phone} | {:error, Ecto.Changeset.t()}
  @spec parse(webauthn) :: {:ok, webauthn} | {:error, Ecto.Changeset.t()}
  def parse(%{factor_type: :totp} = attrs) do
    {%{}, @totp_types}
    |> cast(attrs, [:factor_type, :friendly_name, :issuer])
    |> validate_required([:factor_type])
    |> apply_action(:parse)
  end

  def parse(%{factor_type: :phone} = attrs) do
    {%{}, @phone_types}
    |> cast(attrs, [:factor_type, :friendly_name, :phone])
    |> validate_required([:factor_type, :phone])
    |> apply_action(:parse)
  end

  def parse(%{factor_type: :webauthn} = attrs) do
    {%{}, @webauthn_types}
    |> cast(attrs, [:factor_type, :friendly_name])
    |> validate_required([:factor_type])
    |> apply_action(:parse)
  end
end
