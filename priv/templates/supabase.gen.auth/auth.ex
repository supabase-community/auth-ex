defmodule <%= inspect auth_module %> do
  use <%= inspect web_module %>, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  alias Supabase.Auth
  alias Supabase.Auth.Admin
  alias Supabase.Auth.Session
  alias Supabase.Auth.User

  # Make the remember me cookie valid for 60 days.
  # If you want bump or reduce this value, also change
  # the token expiry itself in #{User} Token.
  @max_age 60 * 60 * 24 * 60
  @remember_me_cookie "_<%= web_app_name %>_user_remember_me"
  @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

  @extra_login_doc """
  It renews the session ID and clears the whole session
  to avoid fixation attacks. See the renew_session
  function to customize this behaviour.

  It also sets a `:live_socket_id` key in the session,
  so LiveView sessions are identified and automatically
  disconnected on log out. The line can be safely removed
  if you are not using LiveView.
  """

  <%= if "password" in strategy do %>
  @doc "Logs the User in using the password strategy.\n" <> @extra_login_doc
  def log_in_user_with_password(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_with_password(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

  <%= if "otp" in strategy do %>
  @doc "Logs the User in using the otp strategy.\n" <> @extra_login_doc
  def log_in_user_with_otp(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_with_otp(client, params) do
      do_login(conn, session, params)
    end
  end

  @doc "Verifies an OTP token and logs the user in.\n" <> @extra_login_doc
  def verify_otp_and_log_in(conn, params) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.verify_otp(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

  <%= if "sso" in strategy do %>
  @doc "Logs the User in using the sso strategy.\n" <> @extra_login_doc
  def log_in_user_with_sso(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_with_sso(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

  <%= if "id_token" in strategy do %>
  @doc "Logs the User in using the id_token strategy.\n" <> @extra_login_doc
  def log_in_user_with_id_token(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_with_id_token(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

  <%= if "oauth" in strategy do %>
  @doc "Logs the User in using the oauth strategy.\n" <> @extra_login_doc
  def log_in_user_with_oauth(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_with_oauth(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

  <%= if "anon" in strategy do %>
  @doc "Logs the User in using the anon strategy.\n" <> @extra_login_doc
  def log_in_user_anonymously(conn, params \\ %{}) do
    with {:ok, client} <- get_client(),
         {:ok, session} <- Auth.sign_in_anonymously(client, params) do
      do_login(conn, session, params)
    end
  end
  <% end %>

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

  # This function renews the session ID and erases the whole
  # session to avoid fixation attacks. If there is any data
  # in the session you may want to preserve after log in/log out,
  # you must explicitly fetch the session data before clearing
  # and then immediately set it after clearing, for example:
  #
  #     defp renew_session(conn) do
  #       preferred_locale = get_session(conn, :preferred_locale)
  #
  #       conn
  #       |> configure_session(renew: true)
  #       |> clear_session()
  #       |> put_session(:preferred_locale, preferred_locale)
  #     end
  #
  defp renew_session(conn) do
    conn
    |> configure_session(renew: true)
    |> clear_session()
  end

  @doc """
  Logs the user out.

  It clears all session data for safety. See renew_session.
  """
  def log_out_user(conn, scope) do
    {:ok, client} = get_client()
    user_token = get_session(conn, :user_token)
    session = %Session{access_token: user_token}
    user_token && Admin.sign_out(client, session, scope)

    live_socket_id = get_session(conn, :live_socket_id)

    if live_socket_id do
      <%= inspect(endpoint_module) %>.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
    |> renew_session()
    |> delete_resp_cookie(@remember_me_cookie)
    |> redirect(to: ~p"/")
  end

  @doc "Authenticates the #{User} by looking into the session and remember me token."
  def fetch_current_user(conn, _opts) do
    {user_token, conn} = ensure_user_token(conn)
    user = user_token && fetch_user_from_session_token(user_token)
    assign(conn, :current_user, user)
  end

  defp fetch_user_from_session_token(user_token) do
    {:ok, client} = get_client()

    case Auth.get_user(client, %Session{access_token: user_token}) do
      {:ok, %User{} = user} -> user
      _ -> nil
    end
  end

  defp ensure_user_token(conn) do
    if token = get_session(conn, :user_token) do
      {token, conn}
    else
      conn = fetch_cookies(conn, signed: [@remember_me_cookie])

      if token = conn.cookies[@remember_me_cookie] do
        {token, put_token_in_session(conn, token)}
      else
        {nil, conn}
      end
    end
  end

  <%= if live? do %>
  @doc """
  Handles mounting and authenticating the current_user in LiveViews.

  ## `on_mount` arguments

    * `:mount_current_user` - Assigns current_user
      to socket assigns based on user_token, or nil if
      there's no user_token or no matching user.

    * `:ensure_authenticated` - Authenticates the user from the session,
      and assigns the current_user to socket assigns based
      on user_token.
      Redirects to login page if there's no logged user.

    * `:redirect_if_user_is_authenticated` - Authenticates the user from the session.
      Redirects to signed_in_path if there's a logged user.

  ## Examples

  Use the `on_mount` lifecycle macro in LiveViews to mount or authenticate
  the current_user:

      defmodule <%= inspect web_module %>.PageLive do
        use <%= inspect web_module %>, :live_view

        on_mount {<%= inspect auth_module %>, :mount_current_user}
        ...
      end

  Or use the `live_session` of your router to invoke the on_mount callback:

      live_session :authenticated, on_mount: [{<%= inspect auth_module %>, :ensure_authenticated}] do
        live "/profile", ProfileLive, :index
      end
  """
  def on_mount(:mount_current_user, _params, session, socket) do
    {:cont, mount_current_user(socket, session)}
  end

  def on_mount(:ensure_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:cont, socket}
    else
      socket =
        socket
        |> Phoenix.LiveView.put_flash(:error, "You must log in to access this page.")
        |> Phoenix.LiveView.redirect(to: ~p"/login")

      {:halt, socket}
    end
  end

  def on_mount(:redirect_if_user_is_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:halt, Phoenix.LiveView.redirect(socket, to: signed_in_path())}
    else
      {:cont, socket}
    end
  end

  def mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      if user_token = session["user_token"] do
        maybe_get_current_user(%Session{access_token: user_token})
      end
    end)
  end

  defp maybe_get_current_user(session) do
    {:ok, client} = get_client()

    case Auth.get_user(client, session) do
      {:ok, %User{} = user} -> user
      _ -> nil
    end
  end
  <% end %>

  @doc """
  Used for routes that require the user to not be authenticated.
  """
  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
      |> redirect(to: signed_in_path())
      |> halt()
    else
      conn
    end
  end

  @doc """
  Used for routes that require the user to be authenticated.
  """
  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> maybe_store_return_to()
      |> redirect(to: ~p"/login")
      |> halt()
    end
  end

  defp put_token_in_session(conn, token) do
    conn
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, "users_sessions:#{Base.url_encode64(token)}")
  end

  defp maybe_store_return_to(%{method: "GET"} = conn) do
    put_session(conn, :user_return_to, current_path(conn))
  end

  defp maybe_store_return_to(conn), do: conn

  defp signed_in_path(), do: ~p"/"

  <%= if supabase_client do %>
  def get_client, do: <%= supabase_client %>.get_client()
  <% else %>
  def get_client do
    url = <%= inspect supabase_url %>
    key = <%= inspect supabase_key %>
    Supabase.init_client(url, key)
  end
  <% end %>
end
