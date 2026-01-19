defmodule Supabase.Auth.AutoRefreshTest do
  use ExUnit.Case, async: true

  import Mox

  alias Supabase.Auth.AutoRefresh
  alias Supabase.Auth.Session
  alias Supabase.Auth.User
  alias Supabase.Client

  setup :verify_on_exit!

  setup do
    client = %Client{
      auth_url: "https://example.supabase.co/auth/v1",
      api_key: "test-api-key",
      auth: %{storage_key: "sb-test-key"}
    }

    session = %Session{
      access_token: "test-access-token",
      refresh_token: "test-refresh-token",
      expires_in: 3600,
      expires_at: System.os_time(:second) + 3600,
      token_type: "bearer",
      user: %User{id: "test-user-id", email: "test@example.com"}
    }

    {:ok, %{client: client, session: session}}
  end

  describe "needs_refresh?/1" do
    test "returns false when token is not expired" do
      # Create a session with an expiry very far in the future
      # 30 days in the future
      future_time = System.os_time(:second) + 3600 * 24 * 30

      session = %Session{
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        expires_in: 3600 * 24 * 30,
        expires_at: future_time,
        token_type: "bearer"
      }

      refute AutoRefresh.needs_refresh?(session)
    end

    test "returns true when token is about to expire" do
      # Set expiry to be within the refresh threshold
      now = System.os_time(:second)

      session = %Session{
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        expires_in: 60,
        # Very close to expiration
        expires_at: now + 60,
        token_type: "bearer"
      }

      assert AutoRefresh.needs_refresh?(session)
    end

    test "returns false when expires_at is nil" do
      session = %Session{
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        expires_in: 3600,
        expires_at: nil,
        token_type: "bearer"
      }

      refute AutoRefresh.needs_refresh?(session)
    end
  end
end
