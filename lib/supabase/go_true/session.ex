defmodule Supabase.GoTrue.Session do
  @moduledoc """
  This schema is used to validate and parse the parameters for a session.

  ## Fields
    * `provider_token` - The provider token.
    * `provider_refresh_token` - The provider refresh token.
    * `access_token` - The access token.
    * `refresh_token` - The refresh token.
    * `expires_in` - The expiration time.
    * `expires_at` - The expiration date.
    * `token_type` - The token type.
    * `user` - The user. Check the `Supabase.GoTrue.User` schema for more information.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Supabase.GoTrue.User

  @type t :: %__MODULE__{
          provider_token: String.t() | nil,
          provider_refresh_token: String.t() | nil,
          access_token: String.t(),
          refresh_token: String.t(),
          expires_in: integer,
          # unix timestamp
          expires_at: integer | nil,
          token_type: String.t(),
          user: User.t()
        }

  @required_fields ~w[access_token refresh_token expires_in token_type]a
  @optional_fields ~w[provider_token provider_refresh_token expires_at]a

  @derive Jason.Encoder
  @primary_key false
  embedded_schema do
    field(:provider_token, :string)
    field(:provider_refresh_token, :string)
    field(:access_token, :string)
    field(:refresh_token, :string)
    field(:expires_in, :integer)
    field(:expires_at, :integer)
    field(:token_type, :string)

    embeds_one(:user, User)
  end

  @spec parse(map) :: {:ok, t} | {:error, Ecto.Changeset.t()}
  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> cast_embed(:user, required: false)
    |> apply_action(:parse)
  end
end
