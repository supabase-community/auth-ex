defmodule Supabase.Auth.LiveViewTest do
  use ExUnit.Case, async: false

  import Mox
  import Supabase.Auth.UserFixture

  alias Supabase.Fetcher.Request

  @moduletag capture_log: true

  setup :verify_on_exit!

  @mock TestHTTPClient

  setup_all do
    Application.put_env(:supabase_auth, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_auth, :http_client)
    end)
  end

  # Minimal test endpoint for broadcast_from/4
  defmodule TestEndpoint do
    def broadcast_from(_from, _topic, _event, _payload), do: :ok
  end

  # Module that uses the macro — exercises the quote block
  defmodule TestAuth do
    @moduledoc false
    use Supabase.Auth.LiveView,
      endpoint: Supabase.Auth.LiveViewTest.TestEndpoint,
      signed_in_path: "/app",
      not_authenticated_path: "/login"
  end

  defp build_socket(assigns \\ %{}) do
    %Phoenix.LiveView.Socket{
      assigns: Map.merge(%{__changed__: %{}}, assigns)
    }
  end

  setup do
    client = Supabase.init_client!("https://localhost:54321", "test-api-key")
    {:ok, client: client, json: Supabase.json_library()}
  end

  describe "assign_supabase_client/2" do
    test "assigns client to socket", %{client: client} do
      socket = build_socket()
      socket = TestAuth.assign_supabase_client(socket, client)

      assert socket.assigns.supabase_client == client
    end
  end

  describe "on_mount :mount_current_user" do
    test "assigns current_user when user_token is in session", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        body = user_fixture_json(id: "123")
        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      socket = build_socket(%{supabase_client: client})
      session = %{"user_token" => "some-access-token"}

      assert {:cont, socket} = TestAuth.on_mount(:mount_current_user, %{}, session, socket)
      assert %Supabase.Auth.User{id: "123"} = socket.assigns.current_user
      assert socket.assigns.user_token == "some-access-token"
    end

    test "assigns nil current_user when no user_token in session", %{client: client} do
      socket = build_socket(%{supabase_client: client})
      session = %{}

      assert {:cont, socket} = TestAuth.on_mount(:mount_current_user, %{}, session, socket)
      assert is_nil(socket.assigns.current_user)
    end

    test "assigns nil current_user when get_user fails", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        body = Jason.encode!(%{"error" => "invalid token", "message" => "unauthorized"})
        {:ok, %Finch.Response{status: 401, body: body, headers: []}}
      end)

      socket = build_socket(%{supabase_client: client})
      session = %{"user_token" => "invalid-token"}

      assert {:cont, socket} = TestAuth.on_mount(:mount_current_user, %{}, session, socket)
      assert is_nil(socket.assigns.current_user)
    end

    test "raises when supabase_client is not in assigns" do
      socket = build_socket()
      session = %{"user_token" => "some-token"}

      assert_raise RuntimeError, ~r/Supabase client not found/, fn ->
        TestAuth.on_mount(:mount_current_user, %{}, session, socket)
      end
    end
  end

  describe "on_mount :ensure_authenticated" do
    test "continues when user is authenticated", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        body = user_fixture_json(id: "123")
        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      socket = build_socket(%{supabase_client: client})
      session = %{"user_token" => "valid-token"}

      assert {:cont, socket} = TestAuth.on_mount(:ensure_authenticated, %{}, session, socket)
      assert socket.assigns.current_user
    end

    test "redirects when user is not authenticated", %{client: client} do
      socket = build_socket(%{supabase_client: client})
      session = %{}

      assert {:halt, socket} = TestAuth.on_mount(:ensure_authenticated, %{}, session, socket)
      assert socket.redirected == {:redirect, %{status: 302, to: "/login"}}
    end
  end

  describe "on_mount :redirect_if_user_is_authenticated" do
    test "redirects when user is authenticated", %{client: client} do
      expect(@mock, :request, fn %Request{}, _opts ->
        body = user_fixture_json(id: "123")
        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      socket = build_socket(%{supabase_client: client})
      session = %{"user_token" => "valid-token"}

      assert {:halt, socket} =
               TestAuth.on_mount(:redirect_if_user_is_authenticated, %{}, session, socket)

      assert socket.redirected == {:redirect, %{status: 302, to: "/app"}}
    end

    test "continues when user is not authenticated", %{client: client} do
      socket = build_socket(%{supabase_client: client})
      session = %{}

      assert {:cont, _socket} =
               TestAuth.on_mount(:redirect_if_user_is_authenticated, %{}, session, socket)
    end
  end
end
