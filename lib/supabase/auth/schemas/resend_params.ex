defmodule Supabase.Auth.Schemas.ResendParams do
  @moduledoc """
  Parameters for resending confirmation or verification emails/SMS.

  This schema is used by `Supabase.Auth.resend/3` to define the parameters
  for resending verification codes or confirmation emails to users.

  ## Fields

  * `type` - The type of verification to resend (`:sms`, `:signup`, `:phone_change`, `:email_change`)
  * `options` - Additional options:
    * `email_redirect_to` - URL to redirect after email confirmation
    * `captcha_token` - Token from CAPTCHA verification if enabled
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Supabase.Auth.Validations

  @type otp_type :: :sms | :signup | :phone_change | :email_change

  @type options :: %__MODULE__.Options{
          email_redirect_to: URI.t() | nil,
          captcha_token: String.t() | nil
        }

  @type t :: %__MODULE__{
          type: otp_type,
          options: options
        }

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
  @primary_key false
  embedded_schema do
    field(:type, Ecto.Enum, values: ~w[sms signup phone_change email_change]a)

    embeds_one :options, Options, primary_key: false do
      @moduledoc false
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
    cast(%__MODULE__.Options{}, changeset.params["options"], [:email_redirect_to, :captcha_token])
  end
end
