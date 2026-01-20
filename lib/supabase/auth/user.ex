defmodule Supabase.Auth.User do
  @moduledoc """
  Represents a user profile in the Supabase authentication system.

  This schema contains all the user information stored in the Auth service, including
  authentication details, profile data, and linked identities. The User struct is typically
  accessed through `Supabase.Auth.get_user/2` after a successful authentication.

  ## Important Fields

  * `id` - Unique identifier (UUID) for the user
  * `email` - User's email address (if applicable)
  * `phone` - User's phone number (if applicable)
  * `user_metadata` - Custom user attributes, editable by the user
  * `app_metadata` - Application-controlled attributes, not editable by the user
  * `created_at` - Timestamp when the user was created
  * `last_sign_in_at` - Timestamp of the user's most recent sign-in
  * `confirmed_at` - Timestamp when the user was confirmed (email verification)
  * `factors` - Multi-factor authentication methods associated with the user
  * `identities` - External identity providers linked to this user (GitHub, Google, etc.)
  * `is_anonymous` - Set to true if user is authenticated as anonymous

  ## Confirmation Status

  A user's verification status for email and phone can be determined using the following fields:

  * `email_confirmed_at` - Non-nil when email is verified
  * `phone_confirmed_at` - Non-nil when phone is verified

  ## Example Usage

  ```elixir
  # Retrieve user details from a session
  {:ok, user} = Supabase.Auth.get_user(client, session)

  # Check if email is verified
  email_verified = user.email_confirmed_at != nil

  # Access custom user metadata
  profile_pic = user.user_metadata["avatar_url"]
  ```

  ## Related Schemas

  * `Supabase.Auth.User.Factor` - MFA factors associated with the user
  * `Supabase.Auth.User.Identity` - External identity providers linked to the user
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Supabase.Auth.User.Factor
  alias Supabase.Auth.User.Identity

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
          factors: list(Factor) | nil,
          is_anonymous: boolean | nil
        }

  @required_fields ~w[id app_metadata aud created_at]a
  @optional_fields ~w[user_metadata confirmation_sent_at recovery_sent_at email_change_sent_at new_email new_phone invited_at action_link email phone confirmed_at email_confirmed_at phone_confirmed_at last_sign_in_at role is_anonymous]a

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
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
    field(:is_anonymous, :boolean)

    embeds_many(:factors, Factor)
    embeds_many(:identities, Identity)

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

  @doc """
  Parses and validates a map of user attributes into a User struct.

  This function validates that all required fields are present and correctly formatted,
  returning either a valid User struct or a changeset with validation errors.

  ## Parameters

  * `attrs` - Map containing user attributes returned from the Auth API

  ## Returns

  * `{:ok, user}` - Successfully parsed user
  * `{:error, changeset}` - Failed validation with error details

  ## Examples

      iex> attrs = %{
      ...>   "id" => "550e8400-e29b-41d4-a716-446655440000",
      ...>   "email" => "user@example.com",
      ...>   "app_metadata" => %{},
      ...>   "user_metadata" => %{"name" => "Test User"},
      ...>   "aud" => "authenticated",
      ...>   "created_at" => "2023-01-01T00:00:00Z"
      ...> }
      iex> {:ok, user} = Supabase.Auth.User.parse(attrs)
      iex> user.email
      "user@example.com"
  """
  def parse(attrs) do
    attrs
    |> changeset()
    |> apply_action(:parse)
  end

  @doc """
  Parses a list of user attribute maps into a list of User structs.

  This function attempts to validate and parse each map in the provided list.
  If all validations succeed, it returns a list of User structs. If any
  validation fails, it returns the first error encountered.

  ## Parameters

  * `list_attrs` - List of maps containing user attributes

  ## Returns

  * `{:ok, [user, ...]}` - Successfully parsed list of users
  * `{:error, changeset}` - First validation error encountered

  ## Examples

      iex> attrs_list = [
      ...>   %{"id" => "user1", "app_metadata" => %{}, "aud" => "auth", "created_at" => "2023-01-01T00:00:00Z"},
      ...>   %{"id" => "user2", "app_metadata" => %{}, "aud" => "auth", "created_at" => "2023-01-01T00:00:00Z"}
      ...> ]
      iex> {:ok, users} = Supabase.Auth.User.parse_list(attrs_list)
      iex> length(users)
      2
  """
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
