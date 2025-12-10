defmodule Supabase.Auth.Session do
  @moduledoc """
  Represents an authenticated session with Supabase's Auth service.

  A session contains the tokens and metadata necessary for authenticating 
  subsequent API requests. It is returned after a successful sign-in or sign-up operation
  and can be refreshed using `Supabase.Auth.refresh_session/2`.

  ## Fields

  * `access_token` - JWT token used for API authorization (required)
  * `refresh_token` - Token used to obtain a new access token when it expires (required)
  * `expires_in` - Number of seconds until the access token expires (required)
  * `expires_at` - Unix timestamp (in seconds) when the token expires
  * `token_type` - Type of token, usually "bearer" (required)
  * `provider_token` - OAuth provider-specific token (if applicable)
  * `provider_refresh_token` - OAuth provider-specific refresh token (if applicable)
  * `user` - The authenticated user's profile information (`Supabase.Auth.User`)

  ## Usage

  ```elixir
  # Store the session securely after sign-in
  {:ok, session} = Supabase.Auth.sign_in_with_password(client, credentials)

  # Use the session for authenticated requests
  {:ok, user} = Supabase.Auth.get_user(client, session)

  # Refresh the session before it expires
  {:ok, refreshed_session} = Supabase.Auth.refresh_session(client, session.refresh_token)
  ```

  ## Security Notes

  * The access_token contains sensitive information and should be secured appropriately
  * Sessions should be refreshed before they expire to maintain authentication
  * For web applications, it's recommended to store session tokens in HTTP-only cookies
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Supabase.Auth.User

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

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
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
    # Calculate expires_at if not provided but expires_in is available
    attrs =
      if is_nil(attrs[:expires_at]) && attrs[:expires_in] do
        now = System.os_time(:second)
        Map.put(attrs, :expires_at, now + attrs[:expires_in])
      else
        attrs
      end

    %__MODULE__{}
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> cast_embed(:user, required: false)
    |> apply_action(:parse)
  end
end
