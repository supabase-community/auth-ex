defmodule Supabase.GoTrue.Schemas.SignInWithSSO do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in with SSO.

  ## Fields
    * `provider_id` - The provider ID.
    * `domain` - The domain.
    * `options` - The options.
      - `redirect_to` - The redirect URL.
      - `captcha_token` - The captcha token.
  """

  use Ecto.Schema

  import Ecto.Changeset

  import Supabase.GoTrue.Validations

  @type options :: %__MODULE__.Options{
          redirect_to: String.t(),
          captcha_token: String.t()
  }

  @type t :: %__MODULE__{
          provider_id: String.t(),
          domain: String.t(),
          options: options
  }

  embedded_schema do
    field(:provider_id, :string)
    field(:domain, :string)

    embeds_one :options, Options, primary_key: false do
      field(:redirect_to, :string)
      field(:captcha_token, :string)
    end
  end

  def to_sign_in_params(%__MODULE__{} = signin) do
    signin
    |> Map.take([:provider_id, :domain])
    |> Map.put(:redirect_to, signin.options.redirect_to)
  end

  def to_sign_in_params(%__MODULE__{} = signin, code_challenge, code_method) do
    signin
    |> Map.take([:provider_id, :domain])
    |> Map.put(:redirect_to, signin.options.redirect_to)
    |> Map.merge(%{code_challenge: code_challenge, code_challenge_method: code_method})
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, ~w[provider_id domain]a)
    |> validate_required_inclusion(~w[provider_id domain]a)
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
    cast(options, attrs, ~w[redirect_to captcha_token]a)
  end
end
