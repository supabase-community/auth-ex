defmodule Supabase.GoTrue.Schemas.SignInWithOTP do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in with OTP.

  ## Fields
    * `email` - The user's email.
    * `phone` - The user's phone.
    * `options` - The options for signing in with OTP.
      - `data` - The data for the sign in.
      - `email_redirect_to` - The redirect URL for the email.
      - `captcha_token` - The captcha token.
      - `channel` - The channel for the OTP.
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Supabase.GoTrue.Validations

  @type options :: %__MODULE__.Options{
          data: map(),
          email_redirect_to: String.t(),
          captcha_token: String.t(),
          channel: String.t(),
          should_create_user: boolean()
        }

  @type t :: %__MODULE__{
          email: String.t(),
          phone: String.t(),
          options: options
        }

  @primary_key false
  embedded_schema do
    field(:email, :string)
    field(:phone, :string)

    embeds_one :options, Options, primary_key: false do
      field(:data, :map)
      field(:email_redirect_to, :string)
      field(:captcha_token, :string)
      field(:channel, :string, default: "sms")
      field(:should_create_user, :boolean, default: true)
    end
  end

  def to_sign_in_params(%__MODULE__{email: email} = signin, code_challenge, code_method)
      when not is_nil(email) do
    signin
    |> Map.take([:email])
    |> Map.put(:data, signin.options.data)
    |> Map.put(:captcha_token, signin.options.captcha_token)
    |> Map.put(:create_user, signin.options.should_create_user)
    |> Map.put(:redirect_to, signin.options.email_redirect_to)
    |> Map.merge(%{code_challange: code_challenge, code_challenge_method: code_method})
  end

  def to_sign_in_params(%__MODULE__{phone: phone} = signin, code_challenge, code_method)
      when not is_nil(phone) do
    signin
    |> Map.take([:phone])
    |> Map.put(:data, signin.options.data)
    |> Map.put(:captcha_token, signin.options.captcha_token)
    |> Map.put(:create_user, signin.options.should_create_user)
    |> Map.put(:channel, signin.options.channel)
    |> Map.merge(%{code_challange: code_challenge, code_challenge_method: code_method})
  end

  def to_sign_in_params(%__MODULE__{email: email} = signin) when not is_nil(email) do
    signin
    |> Map.take([:email])
    |> Map.put(:data, signin.options.data)
    |> Map.put(:captcha_token, signin.options.captcha_token)
    |> Map.put(:create_user, signin.options.should_create_user)
    |> Map.put(:redirect_to, signin.options.email_redirect_to)
  end

  def to_sign_in_params(%__MODULE__{phone: phone} = signin) when not is_nil(phone) do
    signin
    |> Map.take([:phone])
    |> Map.put(:data, signin.options.data)
    |> Map.put(:captcha_token, signin.options.captcha_token)
    |> Map.put(:create_user, signin.options.should_create_user)
    |> Map.put(:channel, signin.options.channel)
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, ~w[email phone]a)
    |> validate_required_inclusion(~w[email phone]a)
    |> cast_embed(:options, with: &options_changeset/2, required: false)
    |> maybe_put_default_options()
    |> apply_action(:parse)
  end

  defp maybe_put_default_options(%{valid?: false} = c), do: c

  defp maybe_put_default_options(changeset) do
    if get_embed(changeset, :options) do
      changeset
    else
      put_embed(changeset, :options, %__MODULE__.Options{})
    end
  end

  defp options_changeset(options, attrs) do
    cast(options, attrs, ~w[data email_redirect_to channel should_create_user captcha_token]a)
  end
end
