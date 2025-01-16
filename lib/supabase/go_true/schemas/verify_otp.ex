defmodule Supabase.GoTrue.Schemas.VerifyOTP do
  @moduledoc """
  This schema is used to validate and parse the parameters for verifying an OTP.

  ## Fields

  ### Mobile OTP
    * `phone` - The user's phone number.
    * `token` - The OTP token.
    * `type` - The type of OTP.
    * `options` - The options for the OTP.
      - `redirect_to` - The redirect URL.
      - `captcha_token` - The captcha token.

  ### Email OTP
    * `email` - The user's email.
    * `token` - The OTP token.
    * `type` - The type of OTP.
    * `options` - The options for the OTP.
      - `redirect_to` - The redirect URL.
      - `captcha_token` - The captcha token.

  ### Token Hash
    * `token_hash` - The token hash.
    * `type` - The type of OTP.
    * `options` - The options for the OTP.
      - `redirect_to` - The redirect URL.
      - `captcha_token` - The captcha token.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type options :: %{redirect_to: String.t(), captcha_token: String.t()}
  @type mobile :: %{phone: String.t(), token: String.t(), type: String.t(), options: options}
  @type email :: %{email: String.t(), token: String.t(), type: String.t(), options: options}
  @type token_hash :: %{token_hash: String.t(), type: String.t(), options: options}
  @type t :: mobile | email | token_hash

  def to_request(%{} = params) do
    with {:ok, data} <- parse(params) do
      captcha_token = get_in(data, [:options, :captcha_token])
      {:ok, Map.put(data, :go_true_security, %{captcha_token: captcha_token})}
    end
  end

  @mobile_otp_types ~w[sms phone_change]a
  @email_otp_types ~w[signup invite magiclink recovery email_change email]a

  @options_types %{redirect_to: :string, captcha_token: :string}

  @mobile_types %{
    phone: :string,
    token: :string,
    type: Ecto.ParameterizedType.init(Ecto.Enum, values: @mobile_otp_types),
    options: :map
  }

  @email_types %{
    email: :string,
    token: :string,
    type: Ecto.ParameterizedType.init(Ecto.Enum, values: @email_otp_types),
    options: :map
  }

  @token_hash_types %{
    token_hash: :string,
    type: Ecto.ParameterizedType.init(Ecto.Enum, values: @email_otp_types),
    options: :map
  }

  def parse(%{phone: _} = attrs) do
    {%{}, @mobile_types}
    |> cast(attrs, [:phone, :token, :type, :options])
    |> validate_required([:phone, :token, :type])
    |> options_changeset()
    |> apply_action(:parse)
  end

  def parse(%{email: _} = attrs) do
    {%{}, @email_types}
    |> cast(attrs, [:email, :token, :type, :options])
    |> validate_required([:email, :token, :type])
    |> options_changeset()
    |> apply_action(:parse)
  end

  def parse(%{token_hash: _} = attrs) do
    {%{}, @token_hash_types}
    |> cast(attrs, [:token_hash, :type, :options])
    |> validate_required([:token_hash, :type])
    |> options_changeset()
    |> apply_action(:parse)
  end

  defp options_changeset(%Ecto.Changeset{valid?: false} = changeset), do: changeset

  defp options_changeset(%Ecto.Changeset{} = changeset) do
    if options = get_change(changeset, :options) do
      {%{}, @options_types}
      |> cast(options, Map.keys(@options_types))
      |> apply_action(:parse)
      |> case do
        {:ok, option} -> put_change(changeset, :options, option)
        {:error, error_changeset} ->
          for {field, {err, info}} <- error_changeset.errors, reduce: changeset do
            changeset -> add_error(changeset, "options.#{field}", err, info)
          end
      end
    else
      changeset
    end
  end
end
