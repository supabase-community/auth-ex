@doc """
Setup helper that registers and logs in users.

    setup :register_and_log_in_user

It stores an updated connection and a registered user in the
test context.
"""
def register_and_log_in_user(%{conn: conn}) do
  user = user_fixture()
  session = session_fixture(user.id)
  %{conn: log_in_user(conn, user, session), user: user, session: session}
end

@doc """
Logs the given `user` into the `conn`.

It returns an updated `conn`.
"""
def log_in_user(conn, user, session) do
  token = session.access_token

  conn
  |> Phoenix.ConnTest.init_test_session(%{})
  |> Plug.Conn.put_session(:user_token, token)
  |> Plug.Conn.put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
  |> Phoenix.ConnTest.put_req_cookie(remember_me_cookie(), token, remember_me_options())
  |> fetch_current_user([])
end

def remember_me_cookie, do: "_<%= web_app_name %>_user_remember_me"

def remember_me_options, do: [sign: true, max_age: 60 * 60 * 24 * 60, same_site: "Lax"]
