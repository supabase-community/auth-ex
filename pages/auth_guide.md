# Authentication with Supabase Auth in Elixir

This guide covers how to use Supabase's authentication service (Auth) with your Elixir applications. It provides examples for the most common authentication scenarios and explains how to integrate authentication with both traditional Phoenix applications and LiveView.

## Authentication Methods

Supabase Auth supports multiple authentication methods:

### Email and Password Authentication

The most common authentication method is email+password sign-in:

```elixir
# Sign in with email and password
{:ok, session} = Supabase.Auth.sign_in_with_password(client, %{
  email: "user@example.com",
  password: "securepassword"
})

# Use the session to get the current user
{:ok, user} = Supabase.Auth.get_user(client, session)
```

### Phone Authentication

Phone-based authentication using SMS verification:

```elixir
# Sign in with phone and password
{:ok, session} = Supabase.Auth.sign_in_with_password(client, %{
  phone: "+15555551234",
  password: "securepassword"
})
```

### One-Time Password (OTP)

OTP is a passwordless authentication method that sends a temporary code to the user's email or phone:

```elixir
# Request an OTP to be sent
:ok = Supabase.Auth.sign_in_with_otp(client, %{
  email: "user@example.com"
})

# Later, verify the OTP to get a session
{:ok, session} = Supabase.Auth.verify_otp(client, %{
  email: "user@example.com",
  token: "123456",
  type: "email"
})
```

### OAuth (Social Authentication)

Sign in with social providers like Google, GitHub, etc.:

```elixir
# Get the OAuth URL to redirect the user to
{:ok, provider, redirect_url} = Supabase.Auth.sign_in_with_oauth(client, %{
  provider: :github,
  redirect_to: "https://myapp.com/auth/callback"
})

# After OAuth callback, exchange the code for a session
{:ok, session} = Supabase.Auth.exchange_code_for_session(client, auth_code, code_verifier)
```

### Single Sign-On (SSO)

Enterprise single sign-on for organizations:

```elixir
# Start SSO authentication
{:ok, redirect_url} = Supabase.Auth.sign_in_with_sso(client, %{
  domain: "example.org",
  redirect_to: "https://myapp.com/auth/callback"
})
```

### Anonymous Authentication

Create a session without user credentials:

```elixir
{:ok, session} = Supabase.Auth.sign_in_anonymously(client)
```

## Session Management

A successful authentication returns a `Session` struct containing tokens and user information:

```elixir
%Supabase.Auth.Session{
  access_token: "eyJhbGciOiJ...",
  refresh_token: "kIvYW5...",
  expires_in: 3600,
  expires_at: 1650123456, # Unix timestamp when token expires
  token_type: "bearer",
  user: %Supabase.Auth.User{...}
}
```

### Refreshing Sessions

To keep users logged in, refresh the session before the access token expires:

```elixir
{:ok, new_session} = Supabase.Auth.refresh_session(client, session.refresh_token)
```

### Session Helper Functions

The `Supabase.Auth.Session` module provides helper functions for session validation and expiry management:

#### Checking Session Expiry

```elixir
# Check if session is expired
if Session.expired?(session) do
  # Token has expired
end

# Check if session is expiring soon (within 5 minutes by default)
if Session.expiring_soon?(session) do
  # Token will expire soon, consider refreshing
end

# Custom expiry margin (check if expiring within 1 minute)
if Session.expiring_soon?(session, within: 60) do
  # Token expires in less than 60 seconds
end

# Check if session needs refresh (expired or expiring soon)
if Session.needs_refresh?(session) do
  # Should refresh the session
end
```

#### Session Validation

```elixir
# Check if session is valid (has tokens and not expired)
if Session.valid?(session) do
  # Session is valid and can be used
end

# Get seconds until expiry (returns nil if no expiry set)
seconds_left = Session.seconds_until_expiry(session)
```

#### Smart Session Refresh

Use helper functions to refresh sessions only when needed:

```elixir
# Refresh only if expiring soon or expired
case Supabase.Auth.refresh_if_needed(client, session) do
  {:ok, new_session} ->
    # Returns original session if not expiring, or refreshed session
    new_session
  {:error, reason} ->
    # Handle refresh error
end

# Custom expiry margin (refresh if expiring within 60 seconds)
{:ok, session} = Supabase.Auth.refresh_if_needed(client, session, within: 60)

# Force refresh even if not expiring
{:ok, session} = Supabase.Auth.refresh_if_needed(client, session, force: true)
```

#### Comprehensive Session Validation

Validate session tokens and refresh if needed in one operation:

```elixir
case Supabase.Auth.ensure_valid_session(client, session) do
  {:ok, valid_session} ->
    # Guaranteed to have valid, non-expiring session
    make_api_call(valid_session)

  {:error, :invalid_session} ->
    # Session is malformed (missing tokens)
    redirect_to_login()

  {:error, :refresh_failed} ->
    # Couldn't refresh expired session
    redirect_to_login()
end
```

## User Management

### User Registration

Create a new user with email and password:

```elixir
{:ok, user_or_session} = Supabase.Auth.sign_up(client, %{
  email: "new_user@example.com",
  password: "securepassword"
})
```

### Getting User Information

Retrieve current user details:

```elixir
{:ok, user} = Supabase.Auth.get_user(client, session)
```

### Updating User Information

Update user profile details:

```elixir
{:ok, updated_conn} = Supabase.Auth.update_user(client, conn, %{
  data: %{
    display_name: "Jane Doe",
    avatar_url: "https://example.com/avatar.png"
  }
})
```

### Password Recovery

Send a password reset email:

```elixir
:ok = Supabase.Auth.reset_password_for_email(client, 
  "user@example.com", 
  redirect_to: "https://myapp.com/reset-password"
)
```

## Multi-factor Authentication (MFA)

Auth supports multi-factor authentication for additional security:

### Managing MFA Factors

```elixir
# Get user's MFA factors
{:ok, user} = Supabase.Auth.get_user(client, session)
factors = user.factors

# Check if user has MFA enabled
has_mfa = length(factors) > 0
```

## Identity Management

Auth allows users to link multiple authentication methods to a single account:

### Linking New Identity Providers

```elixir
# Get a URL to link a new provider
{:ok, %{provider: :github, url: redirect_url}} = Supabase.Auth.link_identity(
  client, 
  session, 
  %{provider: :github}
)

# Redirect user to this URL to link their GitHub account
```

### Unlinking Providers

```elixir
# Remove a linked identity
:ok = Supabase.Auth.unlink_identity(client, session, identity_id)
```

### Listing Linked Identities

```elixir
# Get all linked identities
{:ok, identities} = Supabase.Auth.get_user_identities(client, session)
```

## Server Information

Get information about the Auth server:

```elixir
# Get server settings
{:ok, settings} = Supabase.Auth.get_server_settings(client)

# Check server health
{:ok, health} = Supabase.Auth.get_server_health(client)
```

## Integration with Phoenix

### Traditional Phoenix Applications

For Phoenix applications with traditional views, use the `Supabase.Auth.Plug` module:

```elixir
# lib/my_app_web/auth.ex
defmodule MyAppWeb.Auth do
  use Supabase.Auth.Plug,
    client: MyApp.Supabase.Client,
    endpoint: MyAppWeb.Endpoint,
    signed_in_path: "/app", 
    not_authenticated_path: "/login",
    session_cookie: "my_app_session"
end

# lib/my_app_web/router.ex
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

# lib/my_app_web/controllers/session_controller.ex
defmodule MyAppWeb.SessionController do
  import MyAppWeb.Auth
  
  def create(conn, %{"email" => email, "password" => password}) do
    case log_in_with_password(conn, %{email: email, password: password}) do
      {:ok, conn} ->
        conn
        |> put_flash(:info, "Welcome back!")
        |> redirect(to: Routes.dashboard_path(conn, :index))
        
      {:error, _reason} ->
        conn
        |> put_flash(:error, "Invalid email/password")
        |> render("new.html")
    end
  end
end
```

### Phoenix LiveView Applications

For LiveView applications, use the `Supabase.Auth.LiveView` module:

```elixir
# lib/my_app_web/auth.ex
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

## Best Practices

1. **Secure Token Storage**: Store tokens in HTTP-only cookies for web applications to prevent XSS attacks.

2. **Proactive Token Refresh**: Use `refresh_if_needed/3` or `ensure_valid_session/3` to automatically refresh tokens before expiration:

   ```elixir
   # In your Plug pipeline
   def fetch_current_user(conn, _opts) do
     with token when not is_nil(token) <- get_session(conn, :user_token),
          session <- build_session_from_token(token),
          {:ok, valid_session} <- Supabase.Auth.ensure_valid_session(client(), session) do
       assign(conn, :current_session, valid_session)
     else
       _ -> assign(conn, :current_session, nil)
     end
   end
   ```

   ```elixir
   # In LiveView for long-lived sessions
   def mount(_params, session, socket) do
     if connected?(socket) do
       # Check session every 5 minutes
       Process.send_after(self(), :check_session, :timer.minutes(5))
     end
     {:ok, assign(socket, :session, session)}
   end

   def handle_info(:check_session, socket) do
     session = socket.assigns.session

     case Supabase.Auth.refresh_if_needed(client(), session, within: 300) do
       {:ok, new_session} ->
         Process.send_after(self(), :check_session, :timer.minutes(5))
         {:noreply, assign(socket, :session, new_session)}
       {:error, _} ->
         {:noreply, redirect(socket, to: "/login")}
     end
   end
   ```

3. **Session Validation**: Always validate sessions before making authenticated API calls using `Session.valid?/1`.

4. **Error Handling**: Properly handle authentication errors and provide feedback to users.

5. **HTTPS**: Always use HTTPS in production to protect authentication data.

6. **Rate Limiting**: Implement rate limiting for authentication endpoints to prevent brute force attacks.

## Conclusion

This guide covered the essentials of using Supabase's Auth authentication service with Elixir applications. For more detailed information on specific functions, refer to the module documentation.