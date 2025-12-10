defmodule Supabase.Auth.AuthTemplateTest do
  use ExUnit.Case

  import Phoenix.ConnTest
  import Plug.Conn

  alias Supabase.Auth.Session
  alias Supabase.Auth.User

  defmodule TestWeb do
    @moduledoc false
    def verified_routes do
      %{}
    end
  end

  defmodule TestWeb.Auth do
    @moduledoc false
    import Phoenix.Controller
    import Plug.Conn

    @max_age 60 * 60 * 24 * 60
    @remember_me_cookie "_test_app_user_remember_me"
    @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

    def log_in_user_with_password(conn, params \\ %{}) do
      session = %Session{
        access_token: "test_token_123",
        refresh_token: "refresh_token_123",
        expires_in: 3600,
        token_type: "bearer"
      }

      do_login(conn, session, params)
    end

    defp do_login(conn, session, params) do
      user_return_to = get_session(conn, :user_return_to)

      conn
      |> renew_session()
      |> put_token_in_session(session.access_token)
      |> maybe_write_remember_me_cookie(session, params)
      |> fetch_current_user([])
      |> redirect(to: user_return_to || signed_in_path())
    end

    defp maybe_write_remember_me_cookie(conn, session, %{"remember_me" => "true"}) do
      put_resp_cookie(conn, @remember_me_cookie, session.access_token, @remember_me_options)
    end

    defp maybe_write_remember_me_cookie(conn, _session, _params) do
      conn
    end

    defp renew_session(conn) do
      conn
      |> configure_session(renew: true)
      |> clear_session()
    end

    def fetch_current_user(conn, _opts) do
      {user_token, conn} = ensure_user_token(conn)
      user = user_token && fetch_user_from_session_token(user_token)
      assign(conn, :current_user, user)
    end

    defp fetch_user_from_session_token("test_token_123") do
      %User{
        id: "123",
        email: "test@example.com",
        role: "authenticated"
      }
    end

    defp fetch_user_from_session_token(_), do: nil

    defp ensure_user_token(conn) do
      if token = get_session(conn, :user_token) do
        {token, conn}
      else
        conn = fetch_cookies(conn, signed: [@remember_me_cookie])
        token = conn.cookies[@remember_me_cookie]

        if token do
          {token, put_token_in_session(conn, token)}
        else
          {nil, conn}
        end
      end
    end

    def redirect_if_user_is_authenticated(conn, _opts) do
      if conn.assigns[:current_user] do
        conn
        |> redirect(to: signed_in_path())
        |> halt()
      else
        conn
      end
    end

    defp put_token_in_session(conn, token) do
      conn
      |> put_session(:user_token, token)
      |> put_session(:live_socket_id, "users_sessions:\#{Base.url_encode64(token)}")
    end

    defp signed_in_path, do: "/"
  end

  describe "authentication flow" do
    setup do
      conn = Plug.Test.init_test_session(Phoenix.ConnTest.build_conn(), %{})
      {:ok, conn: conn}
    end

    test "login sets user in session and assigns", %{conn: conn} do
      conn = TestWeb.Auth.log_in_user_with_password(conn, %{})

      assert get_session(conn, :user_token) == "test_token_123"

      assert conn.assigns[:current_user]
      assert conn.assigns.current_user.email == "test@example.com"
    end

    test "fetch_current_user loads user from session", %{conn: conn} do
      conn = put_session(conn, :user_token, "test_token_123")

      conn = TestWeb.Auth.fetch_current_user(conn, [])

      assert conn.assigns[:current_user]
      assert conn.assigns.current_user.email == "test@example.com"
    end

    test "redirect_if_user_is_authenticated redirects when user is logged in", %{conn: conn} do
      conn =
        conn
        |> put_session(:user_token, "test_token_123")
        |> TestWeb.Auth.fetch_current_user([])

      conn = TestWeb.Auth.redirect_if_user_is_authenticated(conn, [])

      assert conn.halted
      assert redirected_to(conn) == "/"
    end

    test "redirect_if_user_is_authenticated allows access when no user", %{conn: conn} do
      conn = TestWeb.Auth.redirect_if_user_is_authenticated(conn, [])

      refute conn.halted
    end
  end
end
