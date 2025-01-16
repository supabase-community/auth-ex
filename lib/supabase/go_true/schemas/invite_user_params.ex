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
    field(:redirect_to, :map)
  end

  def parse(attrs) do
    %__MODULE__{}
    |> cast(attrs, [:data, :redirect_to])
    |> parse_uri()
    |> apply_action(:parse)
  end

  defp parse_uri(changeset) do
    redirect_to = get_change(changeset, :redirect_to)

    if redirect_to do
      case URI.new(redirect_to) do
        {:ok, uri} -> put_change(changeset, :redirect_to, uri)
        {:error, reason} -> add_error(changeset, :redirect_to, "Invalid URI: #{reason}")
      end
    else
      changeset
    end
  end
end
