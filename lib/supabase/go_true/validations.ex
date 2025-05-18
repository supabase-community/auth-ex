defmodule Supabase.GoTrue.Validations do
  @moduledoc false

  import Ecto.Changeset

  @spec validate_required_inclusion(changeset :: Ecto.Changeset.t(), fields :: [atom()]) ::
          Ecto.Changeset.t()
  def validate_required_inclusion(%{valid?: false} = c, _), do: c

  def validate_required_inclusion(changeset, fields) do
    if Enum.any?(fields, &present?(changeset, &1)) do
      changeset
    else
      msg = "at least an #{Enum.join(fields, " or ")} is required"

      for field <- fields, reduce: changeset do
        changeset -> add_error(changeset, field, msg)
      end
    end
  end

  defp present?(changeset, field) do
    value = get_change(changeset, field)
    value && value != ""
  end
end
