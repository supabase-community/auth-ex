defmodule Supabase.GoTrue.UserFixture do
  @moduledoc """
  This module is used to generate fixtures for the `Supabase.GoTrue.User` schema.
  """

  alias Supabase.GoTrue.User
  alias Supabase.GoTrue.User.Identity

  @doc "Generate a user fixture."
  def user_fixture(attrs \\ %{}) do
    default = %{
      id: "11111111-1111-1111-1111-111111111111",
      app_metadata: %{"provider" => "email", "providers" => ["email"]},
      user_metadata: nil,
      aud: "authenticated",
      confirmation_sent_at: ~N[2024-01-01 00:00:00],
      invited_at: ~N[2024-01-01 00:00:00],
      email: "example@email.com",
      role: "authenticated",
      factors: [],
      identities: [
        %Identity{
          id: "11111111-1111-1111-1111-111111111111",
          identity_data: %{
            "email" => "example@email.com",
            "email_verified" => false,
            "phone_verified" => false,
            "sub" => "11111111-1111-1111-1111-111111111111"
          },
          provider: :email,
          last_sign_in_at: ~N[2024-01-01 00:00:00],
          user: nil,
          user_id: "11111111-1111-1111-1111-111111111111",
          created_at: ~N[2024-01-01 00:00:00],
          updated_at: ~N[2024-01-01 00:00:00]
        }
      ],
      created_at: ~N[2024-01-01 00:00:00]
    }

    attrs
    |> Map.new()
    |> Enum.into(default)
    |> then(&struct(User, &1))
  end

  def user_fixture_json(attrs \\ %{}) do
    attrs |> user_fixture() |> Jason.encode!()
  end
end
