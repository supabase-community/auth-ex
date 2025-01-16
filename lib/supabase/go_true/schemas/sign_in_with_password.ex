defmodule Supabase.GoTrue.Schemas.SignInWithPassword do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in with a password.

  ## Fields
    * `email` - The user's email.
    * `phone` - The user's phone.
    * `password` - The user's password.
    * `options` - The options for the sign in.
      - `data` - The data for the sign in.
      - `captcha_token` - The captcha token.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          email: String.t() | nil,
          phone: String.t() | nil,
          password: String.t() | nil,
          options:
            %__MODULE__.Options{
              data: map | nil,
              captcha_token: String.t() | nil
            }
            | nil
        }

  @primary_key false
  embedded_schema do
    field(:email, :string)
    field(:phone, :string)
    field(:password, :string)

    embeds_one :options, Options, primary_key: false do
      field(:data, :map)
      field(:captcha_token, :string)
    end
  end

  def to_sign_in_params(%__MODULE__{} = signin) do
    Map.take(signin, [:email, :phone, :password])
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, ~w[email phone password]a)
    |> cast_embed(:options, with: &options_changeset/2, required: false)
    |> validate_required([:password])
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
    cast(options, attrs, ~w[data captcha_token]a)
  end
end
