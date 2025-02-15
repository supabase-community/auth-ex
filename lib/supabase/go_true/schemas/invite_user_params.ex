defmodule Supabase.GoTrue.Schemas.InviteUserParams do
  @moduledoc """
  This schema is used to validate and parse the parameters for inviting a new user.

  ## Fields
    * `data` - The data for the link.
    * `redirect_to` - The redirect URL.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          data: map,
          redirect_to: URI.t()
        }

  embedded_schema do
    field(:data, :map)
    field(:redirect_to, :string)
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, [:data, :redirect_to])
    |> parse_uri()
    |> apply_action(:parse)
  end

  defp parse_uri(changeset) do
    redirect_to = get_change(changeset, :redirect_to)

    cond do
      is_nil(redirect_to) -> changeset
      not is_binary(redirect_to) -> add_error(changeset, :redirect_to, "needs to be a binary")
      true -> put_change(changeset, :redirect_to, URI.parse(redirect_to) |> URI.to_string())
    end
  end
end
