defmodule Supabase.Auth.Schemas.SignInWithWeb3 do
  @moduledoc false

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          chain: :ethereum | :solana,
          message: String.t(),
          signature: String.t(),
          options:
            %__MODULE__.Options{
              captcha_token: String.t() | nil
            }
            | nil
        }

  @chains ~w[ethereum solana]a

  embedded_schema do
    field(:chain, Ecto.Enum, values: @chains)
    field(:message, :string)
    field(:signature, :string)

    embeds_one :options, Options, primary_key: false do
      @moduledoc false
      field(:captcha_token, :string)
    end
  end

  def to_sign_in_params(%__MODULE__{} = signin) do
    signin
    |> Map.take([:message, :signature])
    |> Map.put(:chain, Atom.to_string(signin.chain))
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, ~w[chain message signature]a)
    |> validate_required(~w[chain message signature]a)
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
    cast(options, attrs, ~w[captcha_token]a)
  end
end
