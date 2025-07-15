defmodule Supabase.Auth.Schemas.AdminUserParams do
  @moduledoc false

  import Ecto.Changeset
  import Supabase.Auth.Validations

  @types %{
    app_metadata: :map,
    email_confirm: :boolean,
    phone_confirm: :boolean,
    ban_duration: :string,
    role: :string,
    email: :string,
    phone: :string,
    password: :string,
    nonce: :string
  }

  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> validate_required_inclusion([:email, :phone])
    |> apply_action(:parse)
  end

  def parse_update(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> apply_action(:parse)
  end
end
