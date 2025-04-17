# Supabase GoTrue

> ![WARNING]
> This library is under development and for so expect breaking changes

[Auth](https://supabase.com/docs/guides/auth) implementation for the [Supabase Potion](https://hexdocs.pm/supabase_potion) SDK in Elixir.

## Installation

```elixir
def deps do
  [
    {:supabase_potion, "~> 0.6"},
    {:supabase_gotrue, "~> 0.4"}
  ]
end
```

## Documentation

Comprehensive documentation is available at [HexDocs](https://hexdocs.pm/supabase_gotrue).

### Guides

* [Authentication Guide](https://hexdocs.pm/supabase_gotrue/auth_guide.html) - Complete overview of authentication methods and integration
* [MFA Guide](https://hexdocs.pm/supabase_gotrue/mfa_guide.html) - Learn how to implement Multi-Factor Authentication

## Usage

Firstly you need to initialize your Supabase client(s) as can be found on the [Supabase Potion documentation](https://hexdocs.pm/supabase_potion/readme.html#usage).

Now you can pass the Client to the `Supabase.GoTrue` functions:

```elixir
iex> Supabase.GoTrue.sign_in_with_password(client, %{} = params)
```

> Note that this example consider that you already have a `client` variable with the Supabase client.

> Note that this example consider that you al already configured the `Supabase.GoTrue` module in your configuration file. As mentioned in the [next section](#configuration).

This implementation also exposes an `Supabase.GoTrue.Admin` function to interact with users with super powers:
```elixir
iex> Supabase.GoTrue.Admin.create_user(client, %{} = params)
```

### Examples

There are sample apps in the `examples` directory that demonstrate how to use the `Supabase.GoTrue` module in your application.

Check the [Supabase Potion examples showcase](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#examples)!

### Configuration

You can configure the `Supabase.GoTrue` module in your `config.exs` file:

```elixir
import Config

config :supabase_gotrue, auth_module: MyAppWeb.Auth
```

### Available authentication methods
- [Sign in with ID Token](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_with_id_token/2)
- [Sign in with email and password](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_with_password/2)
- [Sign in with Oauth](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_with_oauth/2)
- [Sign in with OTP](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_with_otp/2)
- [Sign in with SSO](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_with_sso/2)
- [Anonymous Sign in](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_in_anonymously/1)
- [Sign up with email and password](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.html#sign_up/2)

### Plug based applications (or Phoenix "dead views")

`Supabase.GoTrue.Plug` provides Plug-based authentication support for the `Supabase GoTrue` authentication in Elixir applications.

The module offers a series of functions to manage user authentication through HTTP requests in Phoenix applications with **"dead views"** or plain Plug based application. It facilitates operations like signing-in, signing-out, fetch the current user, and more.

To use the `Supabase.GoTrue.Plug` module, you need first to define a module that will handle the authentication in your application:

```elixir
defmodule MyAppWeb.Auth do
  use Supabase.GoTrue.Plug,
    client: MyApp.Supabase.Client,
    endpoint: MyAppWeb.Endpoint, # required if using Phoenix based applications
    signed_in_path: "/app", # required
    not_authenticated_path: "/login", # required
    session_cookie: "my_app_session", # optional
    # optional
    session_cookie_options: [
      http_only: true,
      secure: true,
      same_site: :lax,
      max_age: 86_400
    ]
end
```

> [!WARNING]
> The `client` options must be a module that implements the `Supabase.Client.Behaviour` behaviour.
> It should be a [Self Managed Client](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#self-managed-clients) but it can be a [One off Client](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#one-off-clients) if you correctly manage the client state on your application.

So, considering that you have something like this on your `config.exs`:

```elixir
config :my_app, MyApp.Supabase.Client,
  base_url: "https://myapp.supabase.co",
  api_key: "myapp-api-key"
```

And you have already defined your self managed client module:

```elixir
# lib/my_app/supabase/client.ex
defmodule MyApp.Supabase.Client do
  use Supabase.Client, otp_app: :my_app
end
```

Then you can use the `Supabase.GoTrue.Plug` module! The module define a series of plugs that you can use in your router:

```elixir
import MyAppWeb.Auth

plug :fetch_current_user # this plug will fetch the current user and assign it to the `conn.assigns[:current_user]`
plug :redirect_if_user_is_authenticated # this plug will redirect to the `signed_in_path` if the user is authenticated
plug :require_authenticated_user # this plug will redirect to the `not_authenticated_path` if the user is not authenticated
```

For example, in your Phoenix router you can use your defined authentication handler module like this:

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  import MyAppWeb.Auth

  pipeline :browser do
    # rest of plugs
    plug :fetch_current_user
  end

  # if a user is already authenticted, redirect to the signed_in_path
  # already authenticated users will not be able to access this scope
  scope "/", MyAppWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get "/login", LoginController, :show
    post "/login", LoginController, :create
  end

  # if a user is not authenticated, redirect to the not_authenticated_path
  # not authenticated users will not be able to access this scope
  scope "/app", MyAppWeb do
    pipe_through [:browser, :require_authenticated_user]

    get "/", AppController, :index
  end
end
```

Also, `Supabase.GoTrue.Plug` provides a series of helper functions that you can use in your login/auth controllers, so with your defined module you can use like this:

```elixir
defmodule MyApp.LoginController do
  use MyAppWeb, :controller

  import MyAppWeb.Auth

  def show(conn, _params) do
    render(conn, "login.html")
  end

  def create(conn, %{"email" => email, "password" => password}) do
    case log_in_with_password(conn, %{"email" => email, "password" => password}) do
      {:ok, updated_conn} ->
        # here the `updated_conn` will contain the access token
        # and also will redirect to the `signed_in_path`
        put_flash(updated_conn, :info, "You have successfully signed in!")

      # this clause means that the user provided invalid credentials
      # so we will render the login form again with an error message
      {:error, _reason} ->
        conn
        |> put_flash(:error, "Invalid email or password")
        |> render("login.html")
    end
  end
end
```

The `log_in_with_password/2` exposed by the `Supabase.GoTrue.Plug` module is one of the various ways that you can start a session with the `Supabase GoTrue` authentication service.

For more ways to authenticate users, please refer to the [Supabase.GoTrue module documentation](https://hexdocs.pm/supabase_gotrue/Supabase.GoTrue.htm) and  the [official Supabase documentation](https://supabase.io/docs/gotrue).

If you're new to the `Plug` library, you can learn more about it in the [official documentation](https://hexdocs.pm/plug).

Also if you're new to the [Phoenix framework](https://phoenixframework.org), you can learn more about it in the [official getting started section](https://hexdocs.pm/phoenix/directory_structure.html).

### Phoenix LiveView applications

Similar to the `Supabase.GoTrue.Plug` module, the `Supabase.GoTrue.LiveView` module provides LiveView-based authentication support for the `Supabase GoTrue` authentication in Elixir applications.

`Supabase.GoTrue.LiveView` defines Server Hooks that you can use in your LiveView modules to manage user authentication through WebSocket connections in Phoenix LiveView applications. These hooks are meant to be used as [on-mount](https://hexdocs.pm/phoenix_live_view/Phoenix.LiveView.html#on_mount/1) callbacks in your LiveView modules or [live_session/3](https://hexdocs.pm/phoenix_live_view/Phoenix.LiveView.Router.html#live_session/3) definitions on your router.

To use the `Supabase.GoTrue.LiveView` module, you need first to define a module that will handle the authentication in your application:

```elixir
defmodule MyAppWeb.Auth do
  use Supabase.GoTrue.LiveView,
    client: MyApp.Supabase.Client, # required
    endpoint: MyAppWeb.Endpoint, # required
    signed_in_path: "/app", # required
    not_authenticated_path: "/login" # required
end
```

> [!WARNING]
> The `client` options must be a module that implements the `Supabase.Client.Behaviour` behaviour.
> It should be a [Self Managed Client](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#self-managed-clients) but it can be a [One off Client](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#one-off-clients) if you correctly manage the client state on your application.

So, considering that you have something like this on your `config.exs`:

```elixir
config :my_app, MyApp.Supabase.Client,
  base_url: "https://myapp.supabase.co",
  api_key: "myapp-api-key"
```

And you have already defined your self managed client module:

```elixir
# lib/my_app/supabase/client.ex
defmodule MyApp.Supabase.Client do
  use Supabase.Client, otp_app: :my_app
end
```

Then in your LiveView module, you can use the module that you defined like this:

```elixir
defmodule MyAppWeb.UserLive do
  use MyAppWeb, :live_view

  on_mount {MyAppWeb.Auth, :mount_current_user}
  on_mount {MyAppWeb.Auth, :ensure_authenticated}

  def mount(_params, _session, socket) do
    # here you will have the `socket.assigns[:current_user]` available
    # and if the user is not authenticated, the user will be redirected to the `not_authenticated_path`
    {:ok, socket}
  end
end
```

The usage with the `live_session/3` definition is similar. In your router:

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  scope "/app", MyAppWeb do
    live_session :authenticated,
      on_mount: [
        {MyAppWeb.Auth, :mount_current_user},
        {MyAppWeb.Auth, :ensure_authenticated}
      ] do
      live "/user", UserLive
    end
  end
end
```

If you're new to Phoenix LiveView, you can learn more about it in the [official documentation](https://hexdocs.pm/phoenix_live_view).
