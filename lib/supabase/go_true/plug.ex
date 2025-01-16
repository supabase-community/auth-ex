if Code.ensure_loaded?(Plug) do
  defmodule Supabase.GoTrue.Plug do
    @moduledoc """
    Provides Plug-based authentication support for the Supabase GoTrue authentication in Elixir applications.

    This module offers a series of functions to manage user authentication through HTTP requests in Phoenix applications. It facilitates operations like logging in with a password, logging out users, fetching the current user from a session, and handling route protections based on authentication state.

    ## Configuration

    The module requires some application environment variables to be set:
    - `authentication_client`: The Supabase client used for authentication.
    - `endpoint`: Your web app endpoint, used internally for broadcasting user disconnection events.
    - `signed_in_path`: The route to where socket should be redirected to after authentication
    - `not_authenticated_path`: The route to where socket should be redirect to if user isn't authenticated

    ## Usage

    Typically, you need to define a module to be your Plug Authentication entrypoint and use this module to inject the necessary functions that you will use on your `MyAppWeb.Router`.
    """

    defmacro __using__(opts) do
      alias Supabase.GoTrue.MissingConfig
      module = __CALLER__.module
      MissingConfig.ensure_opts!(opts, module)

      client = opts[:client]
      signed_in_path = opts[:signed_in_path]
      not_authenticated_path = opts[:not_authenticated_path]
      endpoint = opts[:endpoint]
      session_cookie_name = opts[:session_cookie] || "_supabase_go_true_session_cookie"
      session_cookie_options = opts[:session_cookie_options] || [sign: true, same_site: "Lax"]

      # credo:disable-for-next-line
      quote do
        import Plug.Conn
        import Phoenix.Controller

        alias Supabase.GoTrue
        alias Supabase.GoTrue.Admin
        alias Supabase.GoTrue.Session
        alias Supabase.GoTrue.User

        Code.ensure_loaded!(unquote(client))
        if not function_exported?(unquote(client), :get_client, 0) do
          raise Supabase.GoTrue.MissingConfig, key: :client, module: unquote(module)
        end

        @client unquote(client)
        @signed_in_path unquote(signed_in_path)
        @not_authenticated_path unquote(not_authenticated_path)
        @session_cookie unquote(session_cookie_name)
        @session_cookie_options unquote(session_cookie_options)

        @doc """
        Logs in a user using a username and password. Stores the user token in the session and a cookie, if a `"remember_me"` key is present inside `params`.

        For more information on how Supabase login with email and password works, check `Supabase.GoTrue.sign_in_with_password/2`
        """
        def log_in_with_password(conn, params \\ %{}) do
          {:ok, client} = @client.get_client()

          with {:ok, session} <- GoTrue.sign_in_with_password(client, params) do
            do_login(conn, session, params)
          end
        end

        def log_in_with_id_token(conn, params \\ %{}) do
          {:ok, client} = @client.get_client()

          with {:ok, session} <- GoTrue.sign_in_with_id_token(client, params) do
            do_login(conn, session, params)
          end
        end

        def log_in_with_oauth(conn, params \\ %{}) do
          {:ok, client} = @client.get_client()

          with {:ok, session} <- GoTrue.sign_in_with_oauth(client, params) do
            do_login(conn, session, params)
          end
        end

        def log_in_with_sso(conn, params \\ %{}) do
          {:ok, client} = @client.get_client()

          with {:ok, session} <- GoTrue.sign_in_with_sso(client, params) do
            do_login(conn, session, params)
          end
        end

        def log_in_with_otp(conn, params \\ %{}) do
          {:ok, client} = @client.get_client()

          with {:ok, session} <- GoTrue.sign_in_with_otp(client, params) do
            do_login(conn, session, params)
          end
        end

        defp do_login(conn, session, params) do
          user_return_to = get_session(conn, :user_return_to)

          :ok = @client.set_auth(session.access_token)

          conn
          |> renew_session()
          |> put_token_in_session(session.access_token)
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
        def log_out_user(%Plug.Conn{} = conn, scope) do
          {:ok, client} = @client.get_client()
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
        import Supabase.GoTrue.Plug

        pipeline :browser do
          plug :fetch_session # comes from Plug.Conn
          plug :fetch_current_user
          # rest of plug chain...
        end
        ```
        """
        def fetch_current_user(conn, _opts) do
          {user_token, conn} = ensure_user_token(conn)
          user = user_token && fetch_user_from_session_token(user_token)
          assign(conn, :current_user, user)
        end

        defp fetch_user_from_session_token(user_token) do
          {:ok, client} = @client.get_client()

          case GoTrue.get_user(client, %Session{access_token: user_token}) do
            {:ok, %User{} = user} -> user
            _ -> nil
          end
        end

        defp ensure_user_token(conn) do
          if user_token = get_session(conn, :user_token) do
            {user_token, conn}
          else
            conn = fetch_cookies(conn, signed: [@session_cookie])

            if user_token = conn.cookies[@session_cookie] do
              {user_token, put_token_in_session(conn, user_token)}
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

        def put_token_in_session(conn, token) do
          base64_token = Base.url_encode64(token)

          conn
          |> put_session(:user_token, token)
          |> put_session(:live_socket_id, "users_session:#{base64_token}")
        end
      end
    end
  end
end
