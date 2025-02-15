defmodule Supabase.GoTrue.Schemas.ServerHealth do
  @moduledoc """
  This schema is used to validate and parse the parameters for server health.
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
