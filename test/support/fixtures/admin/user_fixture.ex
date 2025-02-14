defmodule Supabase.GoTrue.Admin.UserFixture do
  @moduledoc """
  This module is used to generate a user fixture for testing admin APIs.
  """

  def user_create_fixture(attrs \\ %{}) do
    default = %{
      app_metadata: %{},
      email_confirm: true,
      phone_confirm: true,
      ban_duration: "1",
      role: "admin",
      email: "john@example.com",
      phone: "1234567890",
      password: "password",
      nonce: "11111111-1111-1111-1111-111111111111"
    }

    Enum.into(Map.new(attrs), default)
  end
end
