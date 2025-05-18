@doc """
Setup helper that registers and logs in users.

    setup :register_and_log_in_user

It stores an updated connection and a registered user in the
test context.
"""
def register_and_log_in_user(%{conn: conn}) do
  user = %Supabase.GoTrue.User{id: Ecto.UUID.generate(), email: "user@example.com"}
  session = %Supabase.GoTrue.Session{access_token: "123"}
  %{conn: log_in_user(conn, session), user: user, session: session}
end

def log_in_user(conn, session) do
  token = session.access_token

  conn
  |> Phoenix.ConnTest.init_test_session(%{})
  |> Plug.Conn.put_session(:user_token, token)
  |> Plug.Conn.put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
  |> Phoenix.ConnTest.put_req_cookie("_<%= web_app_name %>_user_remember_me", token)
  |> <%= auth_module %>.fetch_current_user([])
end
