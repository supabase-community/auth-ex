defmodule Supabase.GoTrue.User do
  @moduledoc """
  This schema is used to validate and parse the parameters for a user.

  ## Fields
    * `id` - The user's ID.
    * `app_metadata` - The metadata to associate with the user.
    * `user_metadata` - The user's metadata.
    * `aud` - The user's audience.
    * `confirmation_sent_at` - The time the confirmation was sent.
    * `recovery_sent_at` - The time the recovery was sent.
    * `email_change_sent_at` - The time the email change was sent.
    * `new_email` - The new email.
    * `new_phone` - The new phone.
    * `invited_at` - The time the user was invited.
    * `action_link` - The action link.
    * `email` - The user's email.
    * `phone` - The user's phone.
    * `created_at` - The time the user was created.
    * `confirmed_at` - The time the user was confirmed.
    * `email_confirmed_at` - The time the email was confirmed.
    * `phone_confirmed_at` - The time the phone was confirmed.
    * `last_sign_in_at` - The time the user last signed in.
    * `last_sign_in_ip` - The user's last sign-in IP.
    * `current_sign_in_at` - The time the user last signed in.
    * `current_sign_in_ip` - The user's current sign-in IP.
    * `sign_in_count` - The number of times the user has signed in.
    * `factors` - The user's factors. Check the `Supabase.GoTrue.User.Factor` schema for more information.
    * `identities` - The user's identities. Check the `Supabase.GoTrue.User.Identity` schema for more information.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Supabase.GoTrue.User.Factor
  alias Supabase.GoTrue.User.Identity

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          app_metadata: map,
          user_metadata: map,
          aud: String.t(),
          confirmation_sent_at: NaiveDateTime.t() | nil,
          recovery_sent_at: NaiveDateTime.t() | nil,
          email_change_sent_at: NaiveDateTime.t() | nil,
          new_email: String.t() | nil,
          new_phone: String.t() | nil,
          invited_at: NaiveDateTime.t() | nil,
          action_link: String.t() | nil,
          email: String.t() | nil,
          phone: String.t() | nil,
          created_at: NaiveDateTime.t(),
          confirmed_at: NaiveDateTime.t() | nil,
          email_confirmed_at: NaiveDateTime.t() | nil,
          phone_confirmed_at: NaiveDateTime.t() | nil,
          last_sign_in_at: NaiveDateTime.t() | nil,
          role: String.t() | nil,
          updated_at: NaiveDateTime.t() | nil,
          identities: list(Identity) | nil,
          factors: list(Factor) | nil
        }

  @required_fields ~w[id app_metadata aud created_at]a
  @optional_fields ~w[confirmation_sent_at recovery_sent_at email_change_sent_at new_email new_phone invited_at action_link email phone confirmed_at email_confirmed_at phone_confirmed_at last_sign_in_at role]a

  @derive Jason.Encoder
  @primary_key {:id, :binary_id, autogenerate: false}
  embedded_schema do
    field(:app_metadata, :map)
    field(:user_metadata, :map)
    field(:aud, :string)
    field(:confirmation_sent_at, :naive_datetime)
    field(:recovery_sent_at, :naive_datetime)
    field(:email_change_sent_at, :naive_datetime)
    field(:new_email, :string)
    field(:new_phone, :string)
    field(:invited_at, :naive_datetime)
    field(:action_link, :string)
    field(:email, :string)
    field(:phone, :string)
    field(:confirmed_at, :naive_datetime)
    field(:email_confirmed_at, :naive_datetime)
    field(:phone_confirmed_at, :naive_datetime)
    field(:last_sign_in_at, :naive_datetime)
    field(:encrypted_password, :string)
    field(:role, :string)

    embeds_many(:factors, Supabase.GoTrue.User.Factor)
    embeds_many(:identities, Supabase.GoTrue.User.Identity)

    timestamps(inserted_at: :created_at)
  end

  def changeset(user \\ %__MODULE__{}, attrs) do
    user
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> cast_embed(:identities, required: false)
    |> cast_embed(:factors, required: false)
  end

  def multiple_changeset(user \\ %__MODULE__{}, attrs) do
    user
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end

  def parse(attrs) do
    attrs
    |> changeset()
    |> apply_action(:parse)
  end

  def parse_list(list_attrs) do
    results =
      Enum.reduce_while(list_attrs, [], fn attrs, acc ->
        changeset = multiple_changeset(attrs)

        case result = apply_action(changeset, :parse) do
          {:ok, user} -> {:cont, [user | acc]}
          {:error, _} -> {:halt, result}
        end
      end)

    if is_list(results), do: {:ok, results}, else: results
  end
end
