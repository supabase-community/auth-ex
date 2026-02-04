# Supabase Auth

[![hex.pm](https://img.shields.io/hexpm/v/supabase_auth.svg)](https://hex.pm/packages/supabase_auth)
[![docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/supabase_auth)
[![ci](https://github.com/supabase-community/auth-ex/actions/workflows/ci.yml/badge.svg)](https://github.com/supabase-community/auth-ex/actions/workflows/ci.yml)

[Auth](https://supabase.com/docs/guides/auth) implementation for the [Supabase Potion](https://hexdocs.pm/supabase_potion) SDK in Elixir.

## Installation

```elixir
def deps do
  [
    {:supabase_potion, "~> 0.7"},
    {:supabase_auth, "~> 0.8.0"} # x-release-please-version
  ]
end
```

## Quick Start

1. Configure your Supabase client in `config.exs`:

```elixir
import Config

config :my_app, MyApp.Supabase.Client,
  base_url: "https://myapp.supabase.co",
  api_key: "myapp-api-key"

config :supabase_auth, auth_module: MyAppWeb.Auth
```

2. Create your Supabase client:

```elixir
defmodule MyApp.Supabase.Client do
  use Supabase.Client, otp_app: :my_app
end
```

3. Use the authentication functions:

```elixir
# Sign in with email and password
{:ok, session} = Supabase.Auth.sign_in_with_password(client, %{
  email: "user@example.com",
  password: "secure-password"
})

# Get the current user
{:ok, user} = Supabase.Auth.get_user(client, session)
```

## Documentation

- [HexDocs](https://hexdocs.pm/supabase_auth) - Complete API reference
- [Authentication Guide](https://hexdocs.pm/supabase_auth/auth_guide.html) - Authentication methods and integration
- [MFA Guide](https://hexdocs.pm/supabase_auth/mfa_guide.html) - Multi-Factor Authentication

## Authentication Methods

- Sign in with email/password
- Sign in with phone/password
- Sign in with magic link (OTP)
- OAuth (social) authentication
- Single Sign-On (SSO)
- Anonymous sign in
- Multi-factor authentication

## Integration Options

### Traditional Web Applications (Plug/Phoenix)

```elixir
# Define your auth module
defmodule MyAppWeb.Auth do
  use Supabase.Auth.Plug,
    client: MyApp.Supabase.Client,
    endpoint: MyAppWeb.Endpoint,
    signed_in_path: "/app",
    not_authenticated_path: "/login"
end

# In your router
defmodule MyAppWeb.Router do
  import MyAppWeb.Auth
  
  pipeline :browser do
    plug :fetch_current_user
  end
  
  # Public routes
  scope "/", MyAppWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]
    
    get "/login", SessionController, :new
    post "/login", SessionController, :create
  end
  
  # Protected routes
  scope "/app", MyAppWeb do
    pipe_through [:browser, :require_authenticated_user]
    
    get "/", DashboardController, :index
  end
end
```

### Phoenix LiveView Applications

```elixir
# Define your auth module
defmodule MyAppWeb.Auth do
  use Supabase.Auth.LiveView,
    client: MyApp.Supabase.Client,
    endpoint: MyAppWeb.Endpoint,
    signed_in_path: "/app",
    not_authenticated_path: "/login"
end

# In your LiveView
defmodule MyAppWeb.DashboardLive do
  use MyAppWeb, :live_view
  
  on_mount {MyAppWeb.Auth, :mount_current_user}
  on_mount {MyAppWeb.Auth, :ensure_authenticated}
  
  def mount(_params, _session, socket) do
    # socket.assigns.current_user is available here
    {:ok, assign(socket, page_title: "Dashboard")}
  end
end

# In your router
live_session :authenticated,
  on_mount: [
    {MyAppWeb.Auth, :mount_current_user},
    {MyAppWeb.Auth, :ensure_authenticated}
  ] do
  live "/dashboard", DashboardLive
end
```

## Examples

Check the [Supabase Potion examples showcase](https://github.com/supabase-community/supabase-ex?tab=readme-ov-file#examples) for sample applications.
