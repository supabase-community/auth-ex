defmodule Supabase.Auth.Schemas.UserParams do
  @moduledoc """
  Parameters for updating user profiles.

  This schema is used by `Supabase.Auth.update_user/3` to define the 
  parameters for updating an authenticated user's profile information.

  ## Fields

  * `email` - New email address for the user
  * `phone` - New phone number for the user
  * `password` - New password for the user
  * `data` - Additional user metadata to update
  * `nonce` - Optional nonce for email change verification
  * `email_redirect_to` - URL to redirect after email change confirmation
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
