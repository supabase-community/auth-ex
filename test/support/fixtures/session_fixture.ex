defmodule Supabase.GoTrue.SessionFixture do
  @moduledoc """
  This module is used to generate a session fixture for testing.
  """

  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.UserFixture

  def session_fixture(attrs \\ %{}) do
    default = %{
      provider_token: "11111111-1111-1111-1111-111111111111",
      provider_refresh_token: "11111111-1111-1111-1111-111111111111",
      access_token: "111",
      refresh_token: "111",
      expires_in: 3600,
      expires_at: ~U[2024-01-01 00:00:00.0Z],
      token_type: "bearer",
      user: UserFixture.user_fixture(attrs[:user] || %{})
    }

    Enum.into(Map.new(attrs), default)
    |> then(&struct(Session, &1))
  end

  def session_fixture_json(attrs \\ %{}) do
    session_fixture(attrs) |> Jason.encode!()
  end
end
