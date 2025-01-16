defmodule Supabase.GoTrue.Schemas.UserParams do
  @moduledoc """
  Uuser params schema. This schema is used to validate and parse the parameters for creating a new admin user.

  ## Fields
    * `data` - The metadata to associate with the user.
    * `email` - The user's email.
    * `phone` - The user's phone.
    * `password` - The user's password.
    * `nonce` - The user's nonce.
    * `email_redirect_to` - The user's nonce.
  """

  import Ecto.Changeset

  @type t :: %{
          data: map | nil,
          email: String.t() | nil,
          phone: String.t() | nil,
          password: String.t() | nil,
          nonce: String.t() | nil,
          email_redirect_to: String.t() | nil
        }

  @types %{
    data: :map,
    email: :string,
    phone: :string,
    password: :string,
    nonce: :string,
    email_redirect_to: :string
  }

  def parse(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> apply_action(:parse)
  end

  def parse_update(attrs) do
    {%{}, @types}
    |> cast(attrs, Map.keys(@types))
    |> apply_action(:parse)
  end
end
