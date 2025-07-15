defmodule Supabase.Auth.SessionFixture do
  @moduledoc """
  This module is used to generate a session fixture for testing.
  """

  alias Supabase.Auth.Session
  alias Supabase.Auth.UserFixture

  def session_fixture(attrs \\ %{}) do
    default = %{
      provider_token: "11111111-1111-1111-1111-111111111111",
      provider_refresh_token: "11111111-1111-1111-1111-111111111111",
      access_token: "111",
      refresh_token: "111",
      expires_in: 3600,
      expires_at: 1_000_000_000,
      token_type: "bearer",
      user: UserFixture.user_fixture(attrs[:user] || %{})
    }

    attrs
    |> Map.new()
    |> Enum.into(default)
    |> then(&struct(Session, &1))
  end

  def session_fixture_json(attrs \\ %{}) do
    attrs |> session_fixture() |> Jason.encode!()
  end
end
