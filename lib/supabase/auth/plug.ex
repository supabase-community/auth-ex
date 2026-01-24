if Code.ensure_loaded?(Plug) do
  defmodule Supabase.Auth.Plug do
    @moduledoc """
    Provides Plug-based authentication support for the Supabase Auth authentication in Elixir applications.

    This module offers a series of functions to manage user authentication through HTTP requests in Phoenix applications. It facilitates operations like logging in with a password, logging out users, fetching the current user from a session, and handling route protections based on authentication state.

    ## Configuration

    The module requires some options to be passed:
    - `authentication_client`: The Supabase client used for authentication.
    - `endpoint`: Your web app endpoint, used internally for broadcasting user disconnection events.
    - `signed_in_path`: The route to where socket should be redirected to after authentication
    - `not_authenticated_path`: The route to where socket should be redirect to if user isn't authenticated
    - use_storage_key_namespacing?: Optionally use the `client.auth.storage_key` to namespace the session keys, for example: `"user_token"` comes `"sb-auth-key_user_token"`

    ## Usage

    Typically, you need to define a module to be your Plug Authentication entrypoint and use this module to inject the necessary functions that you will use on your `MyAppWeb.Router`.
    """

    defmacro __using__(opts) do
      alias Supabase.Auth.MissingConfig

      module = __CALLER__.module
      MissingConfig.ensure_opts!(opts, module)

      signed_in_path = opts[:signed_in_path]
      not_authenticated_path = opts[:not_authenticated_path]
      endpoint = opts[:endpoint]
      namespaced_session_name? = opts[:use_storage_key_namespacing?] || false
      session_cookie_name = opts[:session_cookie] || "_supabase_go_true_session_cookie"
      session_cookie_options = opts[:session_cookie_options] || [sign: true, same_site: "Lax"]

      # credo:disable-for-next-line
      quote do
        import Phoenix.Controller
        import Plug.Conn

        alias Supabase.Auth
        alias Supabase.Auth.Admin
        alias Supabase.Auth.Session
        alias Supabase.Auth.User

        @signed_in_path unquote(signed_in_path)
        @not_authenticated_path unquote(not_authenticated_path)
        @session_cookie unquote(session_cookie_name)
        @session_cookie_options unquote(session_cookie_options)

        @doc """
        Logs in a user using a username and password. Stores the user token in the session and a cookie, if a `"remember_me"` key is present inside `params`.

        For more information on how Supabase login with email and password works, check `Supabase.Auth.sign_in_with_password/2`
        """
        def log_in_with_password(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.sign_in_with_password(client, params) do
            do_login(conn, client, session, params)
          end
        end

        def log_in_with_id_token(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.sign_in_with_id_token(client, params) do
            do_login(conn, client, session, params)
          end
        end

        def log_in_with_oauth(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.sign_in_with_oauth(client, params) do
            do_login(conn, client, session, params)
          end
        end

        def log_in_with_sso(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.sign_in_with_sso(client, params) do
            do_login(conn, client, session, params)
          end
        end

        def log_in_with_otp(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.sign_in_with_otp(client, params) do
            do_login(conn, client, session, params)
          end
        end

        @doc """
        Verifies an OTP code and logs in the user if valid.

        For more information on how Supabase OTP verification works, check `Supabase.Auth.verify_otp/2`
        """
        def verify_otp_and_log_in(conn, %Supabase.Client{} = client, params \\ %{}) do
          with {:ok, session} <- Auth.verify_otp(client, params) do
            do_login(conn, client, session, params)
          end
        end

        @doc """
        Refreshes the current session using the refresh token.

        Returns the updated conn if successful, or redirects to login if refresh fails.
        """
        def refresh_session(conn, %Supabase.Client{} = client) do
          refresh_token = get_session(conn, :refresh_token)

          if refresh_token do
            case Auth.refresh_session(client, refresh_token) do
              {:ok, %Session{} = session} -> put_token_in_session(conn, client, session)
              {:error, _} -> renew_session(conn)
            end
          else
            conn
            |> put_flash(:error, "No refresh token found")
            |> redirect(to: @not_authenticated_path)
          end
        end

        @doc """
        Updates the current user's profile information.

        Requires an active session.
        """
        def update_user(conn, %Supabase.Client{} = client, params) do
          user_token = get_session(conn, :user_token)
          session = %Session{access_token: user_token}

          case Auth.update_user(client, session, params) do
            {:ok, user} -> {:ok, assign(conn, :current_user, user)}
            {:error, error} -> {:error, error}
          end
        end

        defp do_login(conn, client, session, params) do
          user_return_to = get_session(conn, :user_return_to)

          conn
          |> renew_session()
          |> put_token_in_session(client, session.access_token)
          |> maybe_write_session_cookie(session, params)
          |> redirect(to: user_return_to || @signed_in_path)
        end

        defp renew_session(conn) do
          conn
          |> configure_session(renew: true)
          |> clear_session()
        end

        defp maybe_write_session_cookie(conn, %Session{} = session, params) do
          case params do
            %{"remember_me" => "true"} ->
              token = session.access_token
              opts = Keyword.put(@session_cookie_options, :max_age, session.expires_in)
              put_resp_cookie(conn, @session_cookie, token, opts)

            _ ->
              conn
          end
        end

        @doc """
        Logs out the user from the application, clearing session data
        """
        def log_out_user(%Plug.Conn{} = conn, %Supabase.Client{} = client, scope) do
          user_token = get_session(conn, :user_token)
          session = %Session{access_token: user_token}
          user_token && Admin.sign_out(client, session, scope)

          live_socket_id = get_session(conn, :live_socket_id)

          if live_socket_id do
            unquote(endpoint).broadcast(live_socket_id, "disconnect", %{})
          end

          conn
          |> renew_session()
          |> redirect(to: @not_authenticated_path)
        end

        @doc """
        Retrieves the current user from the session or a signed cookie, assigning it to the connection's assigns.

        Can be easily used as a plug, for example inside a Phoenix web app
        pipeline in your `YourAppWeb.Router`, you can do something like:
        ```
        import Supabase.Auth.Plug

        pipeline :browser do
          plug :fetch_session # comes from Plug.Conn
          plug :fetch_current_user, client: Supabase.init_client!(..., ...)
          # rest of plug chain...
        end
        ```
        """
        def fetch_current_user(conn, opts) do
          client = Keyword.fetch!(opts, :client)
          {user_token, conn} = ensure_user_token(client, conn)
          user = user_token && fetch_user_from_session_token(client, user_token)
          assign(conn, :current_user, user)
        end

        defp fetch_user_from_session_token(client, user_token) do
          case Auth.get_user(client, %Session{access_token: user_token}) do
            {:ok, %User{} = user} -> user
            _ -> nil
          end
        end

        defp ensure_user_token(client, conn) do
          if user_token = get_session(conn, :user_token) do
            {user_token, conn}
          else
            conn = fetch_cookies(conn, signed: [@session_cookie])
            user_token = conn.cookies[@session_cookie]

            if user_token do
              session = %Session{access_token: user_token, refresh_token: nil}
              {user_token, put_token_in_session(conn, client, session)}
            else
              {nil, conn}
            end
          end
        end

        @doc """
        Redirects an user to the configured `signed_in_path` if it is authenticated, if not, just halts the connection.

        Generaly you wan to use it inside your scopes routes inside `YourAppWeb.Router`:
        ```
        scope "/" do
          pipe_trough [:browser, :redirect_if_user_is_authenticated]

          get "/login", LoginController, :login
        end
        ```
        """
        def redirect_if_user_is_authenticated(conn, _opts) do
          if conn.assigns[:current_user] do
            conn
            |> redirect(to: @signed_in_path)
            |> halt()
          else
            conn
          end
        end

        @doc """
        Ensures an user is authenticated before executing the rest of Plugs chain.

        Generaly you wan to use it inside your scopes routes inside `YourAppWeb.Router`:
        ```
        scope "/" do
          pipe_trough [:browser, :require_authenticated_user]

          get "/super-secret", SuperSecretController, :secret
        end
        ```
        """
        def require_authenticated_user(conn, _opts) do
          if conn.assigns[:current_user] do
            conn
          else
            conn
            |> maybe_store_return_to()
            |> redirect(to: @signed_in_path)
            |> halt()
          end
        end

        defp maybe_store_return_to(%{method: "GET"} = conn) do
          put_session(conn, :user_return_to, current_path(conn))
        end

        defp maybe_store_return_to(conn), do: conn

        def put_token_in_session(conn, client, %Session{} = session) do
          user_session_name =
            if unquote(namespaced_session_name?), do: "#{client.auth.storage_key}_user_token", else: "user_token"

          refresh_token_name =
            if unquote(namespaced_session_name?), do: "#{client.auth.storage_key}_refresh_token", else: "refresh_token"

          socket_id_name =
            if unquote(namespaced_session_name?), do: "#{client.auth.storage_key}_live_socket_id", else: "live_socket_id"

          conn
          |> put_session(user_session_name, session.access_token)
          |> put_session(refresh_token_name, session.refresh_token)
          |> put_session(socket_id_name, "users_session:#{session.access_token}")
        end
      end
    end
  end
end
