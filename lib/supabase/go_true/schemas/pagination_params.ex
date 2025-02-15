defmodule Supabase.GoTrue.Schemas.PaginationParams do
  @moduledoc """
  This schema is used to validate and parse the parameters for pagination.

  ## Fields
    * `page` - The current page.
    * `per_page` - The number of items per page.
  """

  use Ecto.Schema

  import Ecto.Changeset

  def page_params(attrs) do
    schema = %{page: :integer, per_page: :integer}

    {%{}, schema}
    |> cast(attrs, Map.keys(schema))
    |> apply_action(:parse)
  end

  def pagination(attrs) do
    schema = %{next_page: :integer, last_page: :integer, total: :integer}

    {%{next_page: nil}, schema}
    |> cast(attrs, Map.keys(schema))
    |> validate_required([:total, :last_page])
    |> apply_action(:parse)
  end
end
