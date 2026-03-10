if Code.ensure_loaded?(Phoenix.LiveView) do
  defmodule Supabase.Auth.LiveView do
    @moduledoc """
    Provides LiveView integrations for the Supabase Auth authentication in Elixir applications.

    This module enables the seamless integration of authentication flows within Phoenix LiveView applications
    by leveraging the Supabase Auth SDK. It supports operations such as mounting current users, handling
    authenticated and unauthenticated states, and logging out users.

    The Supabase client is provided to LiveView via socket assigns using the `assign_supabase_client/2` helper,
    giving you full control over client lifecycle and enabling easy testing.

    ## Configuration

    The module requires some options to be passed:
    - `endpoint`: Your web app endpoint, used internally for broadcasting user disconnection events.
    - `signed_in_path`: The route to where the socket should be redirected to after authentication
    - `not_authenticated_path`: The route to where the socket should be redirected to if not authenticated

    ## Usage

    Define a module to be your LiveView Authentication entrypoint and use this module to inject the necessary functions:

        defmodule MyAppWeb.UserAuth do
          use Supabase.Auth.LiveView,
            endpoint: MyAppWeb.Endpoint,
            signed_in_path: "/app",
            not_authenticated_path: "/login"
        end

    Then in your LiveView, assign the client in mount/3 before using on_mount callbacks:

        defmodule MyAppWeb.DashboardLive do
          use MyAppWeb, :live_view

          def mount(_params, _session, socket) do
            client = Supabase.init_client!("https://myapp.supabase.co", "your-anon-key")
            socket = MyAppWeb.UserAuth.assign_supabase_client(socket, client)
            {:ok, socket}
          end
        end

    Or use the `on_mount` callback in your router's live_session:

        live_session :authenticated,
          on_mount: [{MyAppWeb.UserAuth, :ensure_authenticated}] do
          live "/dashboard", DashboardLive
        end

    Check `on_mount/4` for more detailed usage instructions on the available callbacks.
    """

    import Phoenix.Component, only: [assign_new: 3]

    alias Phoenix.LiveView.Socket
    alias Supabase.Auth
    alias Supabase.Auth.Session
    alias Supabase.Auth.User
    alias Supabase.Client

    defmacro __using__(opts) do
      alias Supabase.Auth.MissingConfig

      module = __CALLER__.module
      MissingConfig.ensure_opts!(opts, module)

      signed_in_path = opts[:signed_in_path]
      not_authenticated_path = opts[:not_authenticated_path]
      endpoint = opts[:endpoint]

      # credo:disable-for-next-line Credo.Check.Refactor.LongQuoteBlocks
      quote do
        import Phoenix.Component, only: [assign_new: 3]

        alias Phoenix.LiveView.Socket
        alias Supabase.Auth
        alias Supabase.Auth.Admin
        alias Supabase.Auth.Session
        alias Supabase.Auth.User

        @signed_in_path unquote(signed_in_path)
        @not_authenticated_path unquote(not_authenticated_path)

        @doc """
        Assigns the Supabase client to the socket for use in LiveView callbacks.

        Users should call this helper to provide the client before using on_mount callbacks.

        ## Example

            def mount(_params, _session, socket) do
              client = Supabase.init_client!("https://myapp.supabase.co", "your-anon-key")
              socket = assign_supabase_client(socket, client)
              {:ok, socket}
            end
        """
        @spec assign_supabase_client(Socket.t(), Supabase.Client.t()) :: Socket.t()
        def assign_supabase_client(socket, %Supabase.Client{} = client) do
          Phoenix.Component.assign(socket, :supabase_client, client)
        end

        @doc """
        Logs out the user from the session and broadcasts a disconnect event.

        ## Parameters
        - `socket`: The `Phoenix.LiveView.Socket` representing the current LiveView state.
        - `scope`: An optional scope parameter for the logout request. Check `Supabase.Auth.Admin.sign_out/3` for more detailed information.

        ## Examples

            iex> log_out_user(socket, :local)
            # Broadcasts 'disconnect' and removes the user session
        """
        def log_out_user(%Socket{} = socket, %Supabase.Client{} = client, scope) do
          user = socket.assigns.current_user
          user_token = socket.assigns[:user_token]
          session = %Session{access_token: user_token}
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
          client =
            socket.assigns[:supabase_client] ||
              raise "Supabase client not found in socket assigns. Call assign_supabase_client/2 first."

          {:cont, mount_current_user(session, socket, client)}
        end

        def on_mount(:ensure_authenticated, _params, session, socket) do
          client =
            socket.assigns[:supabase_client] ||
              raise "Supabase client not found in socket assigns. Call assign_supabase_client/2 first."

          socket = mount_current_user(session, socket, client)

          if socket.assigns.current_user do
            {:cont, socket}
          else
            {:halt, Phoenix.LiveView.redirect(socket, to: @not_authenticated_path)}
          end
        end

        def on_mount(:redirect_if_user_is_authenticated, _params, session, socket) do
          client =
            socket.assigns[:supabase_client] ||
              raise "Supabase client not found in socket assigns. Call assign_supabase_client/2 first."

          socket = mount_current_user(session, socket, client)

          if socket.assigns.current_user do
            {:halt, Phoenix.LiveView.redirect(socket, to: @signed_in_path)}
          else
            {:cont, socket}
          end
        end

        def on_mount(:ensure_valid_session, _params, session, socket) do
          client =
            socket.assigns[:supabase_client] ||
              raise "Supabase client not found in socket assigns. Call assign_supabase_client/2 first."

          socket = mount_current_session(session, socket, client)

          if socket.assigns.current_session do
            {:cont, socket}
          else
            {:halt, Phoenix.LiveView.redirect(socket, to: @not_authenticated_path)}
          end
        end

        @spec mount_current_session(map, Socket.t(), Supabase.Client.t()) :: Socket.t()
        def mount_current_session(session, socket, client) do
          case session do
            %Session{} -> Auth.LiveView.__mount_current_session__(socket, session, client)
            _ -> assign_new(socket, :current_session, fn -> nil end)
          end
        end

        @spec mount_current_user(map, Socket.t(), Supabase.Client.t()) :: Socket.t()
        def mount_current_user(session, socket, client) do
          session_key = "#{client.auth.storage_key}_user_token"

          case session do
            %{^session_key => user_token} ->
              Auth.LiveView.__mount_current_user__(socket, user_token, client)

            %{"user_token" => user_token} ->
              Auth.LiveView.__mount_current_user__(socket, user_token, client)

            %{} ->
              assign_new(socket, :current_user, fn -> nil end)
          end
        end
      end
    end

    @doc false
    @spec __mount_current_session__(Socket.t(), Session.t(), Client.t()) :: Socket.t()
    def __mount_current_session__(socket, session, %Client{} = client) do
      case Auth.ensure_valid_session(client, session) do
        {:ok, session} -> assign_new(socket, :current_session, fn -> session end)
        _ -> assign_new(socket, :current_session, fn -> nil end)
      end
    end

    @doc false
    @spec __mount_current_user__(Socket.t(), String.t(), Client.t()) :: Socket.t()
    def __mount_current_user__(socket, user_token, %Client{} = client) do
      socket
      |> assign_new(:current_user, fn ->
        session = %Session{access_token: user_token}
        maybe_get_current_user(client, session)
      end)
      |> assign_new(:user_token, fn -> user_token end)
    end

    @dialyzer {:nowarn_function, maybe_get_current_user: 2}
    defp maybe_get_current_user(%Client{} = client, session) do
      case Auth.get_user(client, session) do
        {:ok, %User{} = user} -> user
        {:error, _} -> nil
      end
    end
  end
end
