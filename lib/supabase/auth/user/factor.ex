defmodule Supabase.Auth.User.Factor do
  @moduledoc """
  This schema is used to validate and parse the parameters for a user factor.

  ## Fields
    * `friendly_name` - The friendly name of the factor.
    * `factor_type` - The type of factor.
    * `status` - The status of the factor.
    * `created_at` - The creation date of the factor.
    * `updated_at` - The last update date of the factor.
    * `id` - The factor's ID.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          friendly_name: String.t() | nil,
          factor_type: :totp,
          status: :verified | :unverified,
          created_at: NaiveDateTime.t(),
          updated_at: NaiveDateTime.t()
        }

  @derive Code.ensure_loaded!(Supabase) && Module.concat(Supabase.json_library(), Encoder)
  @primary_key {:id, :binary_id, autogenerate: false}
  embedded_schema do
    field(:friendly_name, :string)
    field(:factor_type, Ecto.Enum, values: ~w[totp]a)
    field(:status, Ecto.Enum, values: ~w[verified unverified]a)

    timestamps(inserted_at: :created_at)
  end

  def changeset(factor \\ %__MODULE__{}, attrs) do
    factor
    |> cast(attrs, ~w[id friendly_name factor_type status created_at updated_at]a)
    |> validate_required(~w[id factor_type status created_at updated_at]a)
  end
end
