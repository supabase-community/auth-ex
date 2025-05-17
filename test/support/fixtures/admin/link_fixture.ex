defmodule Supabase.GoTrue.Admin.LinkFixture do
  @moduledoc """
  This module is used to generate a link fixture for testing.
  """

  def link_fixture(attrs \\ %{}) do
    default = %{
      email_otp: "111111",
      hashed_token: "11111111-1111-1111-1111-111111111111",
      redirect_to: "http://example.com",
      verification_type: "signup",
      action_link: "http://example.com"
    }

    Enum.into(Map.new(attrs), default)
  end

  def link_fixture_json(attrs \\ %{}) do
    attrs |> link_fixture() |> Jason.encode!()
  end
end
