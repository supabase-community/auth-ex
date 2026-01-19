defmodule Supabase.Auth.Schemas.SignUpWithPassword do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset
  import Supabase.Auth.Validations

  @type options :: %__MODULE__.Options{
          email_redirect_to: URI.t() | nil,
          data: map | nil,
          captcha_token: String.t() | nil
        }

  @type t :: %__MODULE__{
          email: String.t() | nil,
          password: String.t(),
          phone: String.t() | nil,
          options: list(options) | nil
        }

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
  @primary_key false
  embedded_schema do
    field(:email, :string)
    field(:password, :string)
    field(:phone, :string)

    embeds_one :options, Options, primary_key: false do
      @moduledoc false
      field(:email_redirect_to, :string)
      field(:data, :map)
      field(:captcha_token, :string)
    end
  end

  def to_sign_up_params(%__MODULE__{} = signup) do
    signup
    |> Map.take([:email, :password, :phone])
    |> Map.put(:data, (signup.options && signup.options.data) || %{})
  end

  def to_sign_up_params(%__MODULE__{} = signup, code_challenge, code_method) do
    signup
    |> to_sign_up_params()
    |> Map.merge(%{code_challange: code_challenge, code_challenge_method: code_method})
  end

  @spec validate(map) :: Ecto.Changeset.t()
  def validate(attrs) do
    %__MODULE__{}
    |> cast(attrs, [:email, :password, :phone])
    |> cast_embed(:options, with: &options_changeset/2, required: false)
    |> maybe_put_default_options()
    |> validate_required_inclusion([:email, :phone])
    |> validate_required([:password])
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

  @spec parse(map) :: {:ok, t} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    attrs
    |> validate()
    |> apply_action(:parse)
  end
end
