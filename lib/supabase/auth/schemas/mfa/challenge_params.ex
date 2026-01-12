defmodule Supabase.Auth.Schemas.MFA.ChallengeParams do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type totp :: %{}
  @type phone :: %{channel: :sms | :whatsapp}
  @type webauthn :: %{
          webauthn: %{
            rp_id: String.t(),
            rp_origins: [String.t()] | nil
          }
        }
  @type t :: totp | phone | webauthn

  @phone_types %{channel: Ecto.ParameterizedType.init(Ecto.Enum, values: [:sms, :whatsapp])}
  @webauthn_types %{webauthn: :map}
  @webauthn_nested_types %{rp_id: :string, rp_origins: {:array, :string}}

  @spec parse(phone) :: {:ok, phone} | {:error, Ecto.Changeset.t()}
  @spec parse(webauthn) :: {:ok, webauthn} | {:error, Ecto.Changeset.t()}
  @spec parse(totp) :: {:ok, totp} | {:error, Ecto.Changeset.t()}
  def parse(%{channel: _} = attrs) do
    {%{}, @phone_types}
    |> cast(attrs, [:channel])
    |> validate_required([:channel])
    |> validate_inclusion(:channel, [:sms, :whatsapp])
    |> apply_action(:parse)
  end

  def parse(%{webauthn: _} = attrs) do
    {%{}, @webauthn_types}
    |> cast(attrs, [:webauthn])
    |> validate_required([:webauthn])
    |> webauthn_changeset()
    |> apply_action(:parse)
  end

  def parse(%{} = attrs) when map_size(attrs) == 0 do
    {:ok, attrs}
  end

  defp webauthn_changeset(%Ecto.Changeset{valid?: false} = changeset), do: changeset

  defp webauthn_changeset(%Ecto.Changeset{} = changeset) do
    if webauthn = get_change(changeset, :webauthn) do
      {:ok, result} =
        {%{}, @webauthn_nested_types}
        |> cast(webauthn, Map.keys(@webauthn_nested_types))
        |> validate_required([:rp_id])
        |> apply_action(:parse)

      put_change(changeset, :webauthn, result)
    else
      changeset
    end
  end
end
