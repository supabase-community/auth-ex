if Code.ensure_loaded?(Phoenix.LiveView) do
  defmodule Supabase.GoTrue.LiveView do
    @moduledoc """
    Provides LiveView integrations for the Supabase GoTrue authentication in Elixir applications.

    This module enables the seamless integration of authentication flows within Phoenix LiveView applications by leveraging the Supabase GoTrue SDK. It supports operations such as mounting current users, handling authenticated and unauthenticated states, and logging out users.

    ## Configuration

    The module requires some application environment variables to be set:
    - `authentication_client`: The Supabase client used for authentication.
    - `endpoint`: Your web app endpoint, used internally for broadcasting user disconnection events.
    - `signed_in_path`: The route to where socket should be redirected to after authentication
    - `not_authenticated_path: The route to where socket should be redirect to if user isn't authenticated

    ## Usage

    Typically, you need to define a module to be your LiveView Authentication entrypoint and use this module to inject the necessary functions that you will use on your `MyAppWeb.Router`, to handle user authentication states through a series of `on_mount` callbacks, which ensure that user authentication logic is processed during the LiveView lifecycle.

    Check `on_mount/4` for more detailed usage instructions on LiveViews

    ### Example

        defmodule MyAppWeb.Auth do
          use Supabase.GoTrue.LiveView,
            endpoint: MyAppWeb.Endpoint,
            client: MyApp.Supabase.Client,
            signed_in_path: "/app",
            not_authenticated_path: "/login"
        end
    """

    defmacro __using__(opts) do
      alias Supabase.GoTrue.MissingConfig
      module = __CALLER__.module
      MissingConfig.ensure_opts!(opts, module)

      client = opts[:client]
      signed_in_path = opts[:signed_in_path]
      not_authenticated_path = opts[:not_authenticated_path]
      endpoint = opts[:endpoint]

      quote do
        import Phoenix.Component, only: [assign_new: 3]

        alias Phoenix.LiveView.Socket
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

        @doc """
        Logs out the user from the session and broadcasts a disconnect event.

        ## Parameters
        - `socket`: The `Phoenix.LiveView.Socket` representing the current LiveView state.
        - `scope`: An optional scope parameter for the logout request. Check `Supabase.GoTrue.Admin.sign_out/3` for more detailed information.

        ## Examples

            iex> log_out_user(socket, :local)
            # Broadcasts 'disconnect' and removes the user session
        """
        def log_out_user(%Socket{} = socket, scope) do
          user = socket.assigns.current_user
          user_token = socket.assigns[:user_token]
          session = %Session{access_token: user_token}
          {:ok, client} = @client.get_client()
          user_token && Admin.sign_out(client, session, scope)

          unquote(endpoint).broadcast_from(
            self(),
            socket.id,
            "disconnect",
            %{user: user}
          )
        end

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
            defmodule PescarteWeb.PageLive do
              use PescarteWeb, :live_view
              on_mount {PescarteWeb.Authentication, :mount_current_user}
              ...
            end
        Or use the `live_session` of your router to invoke the on_mount callback:
            live_session :authenticated, on_mount: [{PescarteWeb.UserAuth, :ensure_authenticated}] do
              live "/profile", ProfileLive, :index
            end
        """
        def on_mount(:mount_current_user, _params, session, socket) do
          {:cont, mount_current_user(session, socket)}
        end

        def on_mount(:ensure_authenticated, _params, session, socket) do
          socket = mount_current_user(session, socket)

          if socket.assigns.current_user do
            {:cont, socket}
          else
            {:halt, Phoenix.LiveView.redirect(socket, to: @not_authenticated_path)}
          end
        end

        def on_mount(:redirect_if_user_is_authenticated, _params, session, socket) do
          socket = mount_current_user(session, socket)

          if socket.assigns.current_user do
            {:halt, Phoenix.LiveView.redirect(socket, to: @signed_in_path)}
          else
            {:cont, socket}
          end
        end

        def mount_current_user(session, socket) do
          case session do
            %{"user_token" => user_token} ->
              socket
              |> assign_new(:current_user, fn ->
                session = %Session{access_token: user_token}
                maybe_get_current_user(session)
              end)
              |> assign_new(:user_token, fn -> user_token end)

            %{} ->
              assign_new(socket, :current_user, fn -> nil end)
          end
        end

        defp maybe_get_current_user(session) do
          {:ok, client} = @client.get_client()

          case GoTrue.get_user(client, session) do
            {:ok, %User{} = user} -> user
            _ -> nil
          end
        end
      end
    end
  end
end
