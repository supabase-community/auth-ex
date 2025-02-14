defmodule Supabase.GoTrue.Schemas.ResendParams do
  @moduledoc """
  This schema is used to validate and parse the parameters for resending a confirmation email.
  """

  use Ecto.Schema

  import Ecto.Changeset

  import Supabase.GoTrue.Validations

  @type otp_type :: :sms | :signup | :phone_change | :email_change

  @type options :: %__MODULE__.Options{
          email_redirect_to: URI.t() | nil,
          captcha_token: String.t() | nil
        }

  @type t :: %__MODULE__{
          type: otp_type,
          options: options
        }

  @derive Jason.Encoder
  @primary_key false
  embedded_schema do
    field(:type, Ecto.Enum, values: ~w[sms signup phone_change email_change]a)

    embeds_one :options, Options, primary_key: false do
      field(:email_redirect_to, :string)
      field(:captcha_token, :string)
    end
  end

  def parse(source \\ %__MODULE__{}, %{} = attrs) do
    source
    |> cast(attrs, [:type])
    |> cast_embed(:options, with: &options_changeset/2, required: false)
    |> validate_required_inclusion([:type])
    |> apply_action(:insert)
  end

  defp options_changeset(changeset, :options) do
    %__MODULE__.Options{}
    |> cast(changeset.params["options"], [:email_redirect_to, :captcha_token])
  end
end
