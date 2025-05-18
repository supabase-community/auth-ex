defmodule Supabase.GoTrue.Schemas.ServerHealth do
  @moduledoc """
  Represents the health information of the GoTrue authentication server.

  This struct is returned by `Supabase.GoTrue.get_server_health/1` and contains
  information about the server's status, version, and other diagnostic data.

  ## Fields

  * `version` - The version of the GoTrue server
  * `name` - The name of the service (typically "GoTrue")
  * `description` - A brief description of the service
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          version: String.t(),
          name: String.t(),
          description: String.t()
        }

  @derive Jason.Encoder
  @primary_key false
  embedded_schema do
    field(:version, :string)
    field(:name, :string)
    field(:description, :string)
  end

  def parse(source \\ %__MODULE__{}, %{} = attrs) do
    source
    |> cast(attrs, [:version, :name, :description])
    |> validate_required([:version, :name, :description])
    |> apply_action(:insert)
  end
end
