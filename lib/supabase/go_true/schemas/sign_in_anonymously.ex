defmodule Supabase.GoTrue.Schemas.SignInAnonymously do
  @moduledoc """
  This schema is used to validate and parse the parameters for signing in anonymously.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          data: map | nil,
          captcha_token: String.t() | nil
        }

  @derive Jason.Encoder
  @primary_key false
  embedded_schema do
    field(:data, :map)
    field(:captcha_token, :string)
  end

  def to_sign_in_params(%__MODULE__{} = signin) do
    Map.take(signin, [:data])
  end

  def parse(source \\ %__MODULE__{}, %{} = attrs) do
    source
    |> cast(attrs, [:data, :captcha_token])
    |> apply_action(:insert)
  end
end
