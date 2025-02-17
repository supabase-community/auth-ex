defmodule Supabase.GoTrue.Schemas.SignInWithIdToken do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in with an ID token.

  ## Fields
    * `provider` - The provider.
    * `token` - The token.
    * `access_token` - The access token.
    * `nonce` - The nonce.
    * `options` - The options.
      - `captcha_token` - The captcha token.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          provider: :google | :apple | :azure | :facebook | :kakao,
          token: String.t(),
          access_token: String.t() | nil,
          nonce: String.t() | nil,
          options:
            %__MODULE__.Options{
              captcha_token: String.t() | nil
            }
            | nil
        }

  @providers ~w[google apple azure facebook kakao]a

  embedded_schema do
    field(:provider, Ecto.Enum, values: @providers)
    field(:token, :string)
    field(:access_token, :string)
    field(:nonce, :string)

    embeds_one :options, Options, primary_key: false do
      field(:captcha_token, :string)
    end
  end

  def to_sign_in_params(%__MODULE__{} = signin) do
    signin
    |> Map.take([:provider, :access_token, :nonce])
    |> Map.update!(:provider, &Atom.to_string/1)
    |> Map.put(:id_token, signin.token)
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, ~w[provider token access_token nonce]a)
    |> validate_required(~w[provider token]a)
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
    cast(options, attrs, ~w[email_redirect_to data captcha_token]a)
  end
end
