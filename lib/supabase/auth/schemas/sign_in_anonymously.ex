defmodule Supabase.Auth.Schemas.SignInAnonymously do
  @moduledoc """
  Parameters for anonymous sign-in.

  This schema is used by `Supabase.Auth.sign_in_anonymously/2` to define the 
  parameters for creating a new anonymous user. Anonymous users can later be 
  converted to permanent users by linking identities or adding credentials.

  ## Fields

  * `data` - Additional user metadata to include with the sign-in request
  * `captcha_token` - Verification token from CAPTCHA challenge if enabled
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
