defmodule Supabase.Auth.User.Identity do
  @moduledoc """
  This schema is used to validate and parse the identity of a user.

  Supports both built-in OAuth providers (google, github, etc.) and custom providers
  defined in Supabase Auth (using the `custom:identifier` format).

  ## Fields
    * `id` - The provider's subject for this identity (e.g. a numeric string
      for Google or GitHub).
    * `identity_id` - The identity UUID as Supabase Auth stores it (the value
      `unlink_identity/3` expects).
    * `email` - The identity email as emitted by the Auth server.
    * `user_id` - The user's ID.
    * `provider` - The OAuth provider (built-in or custom).
    * `created_at` - The user's creation date.
    * `updated_at` - The user's last update date.
    * `identity_data` - The user's identity data.
    * `last_sign_in_at` - The user's last sign-in date.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Supabase.Auth.Types.Provider

  @type t :: %__MODULE__{
          id: String.t(),
          identity_id: Ecto.UUID.t() | nil,
          user_id: Ecto.UUID.t() | nil,
          provider: providers,
          email: String.t() | nil,
          created_at: NaiveDateTime.t() | nil,
          updated_at: NaiveDateTime.t() | nil,
          identity_data: map | nil,
          last_sign_in_at: NaiveDateTime.t() | nil
        }

  @providers Provider.builtins()

  @type providers :: atom() | String.t()

  @required_fields ~w[id provider]a
  @optional_fields ~w[identity_data last_sign_in_at created_at updated_at user_id identity_id email]a

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
  @primary_key false
  embedded_schema do
    field(:id, :string)
    field(:identity_id, :binary_id)
    field(:identity_data, :map)
    field(:provider, Provider)
    field(:email, :string)
    field(:last_sign_in_at, :naive_datetime)

    belongs_to(:user, Supabase.Auth.User, type: :binary_id)

    timestamps(inserted_at: :created_at)
  end

  def changeset(identifty \\ %__MODULE__{}, attrs) do
    identifty
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end

  def providers, do: @providers

  def parse(attrs) do
    attrs
    |> changeset()
    |> apply_action(:parse)
  end

  def parse_list(list_attrs) do
    results =
      Enum.reduce_while(list_attrs, [], fn attrs, acc ->
        changeset = changeset(attrs)

        case result = apply_action(changeset, :parse) do
          {:ok, identity} -> {:cont, [identity | acc]}
          {:error, _} -> {:halt, result}
        end
      end)

    if is_list(results), do: {:ok, results}, else: results
  end
end
