# OAuth Integration Guide

This guide covers implementing OAuth 2.1 authorization flows in your Elixir application using Supabase Auth.

## Overview

The OAuth module provides two main capabilities:
- **Grant Management**: View and revoke third-party app access
- **Authorization Flow**: Handle OAuth consent requests

## Grant Management

Allow users to manage which applications have access to their account.

### Listing Grants

```elixir
def index(conn, _params) do
  session = conn.assigns.session

  case Supabase.Auth.OAuth.list_grants(client(), session) do
    {:ok, grants} -> render(conn, "grants.html", grants: grants)
    {:error, _} -> redirect(conn, to: "/")
  end
end
```

### Revoking Access

```elixir
def revoke(conn, %{"client_id" => client_id}) do
  session = conn.assigns.session

  case Supabase.Auth.OAuth.revoke_grant(client(), session, client_id) do
    :ok -> redirect(conn, to: "/oauth/grants")
    {:error, _} -> redirect(conn, to: "/oauth/grants")
  end
end
```

## Authorization Flow

Handle OAuth consent when users authorize third-party applications.

### Flow Steps

1. User arrives with an `authorization_id` parameter
2. Fetch authorization details
3. Show consent screen (or skip if already consented)
4. Process approval/denial
5. Redirect to the provided URL

### Implementation

```elixir
def authorize(conn, %{"authorization_id" => auth_id}) do
  session = conn.assigns.session

  case Supabase.Auth.OAuth.get_authorization_details(client(), session, auth_id) do
    {:ok, %{redirect_url: url}} when not is_nil(url) ->
      # User already consented, skip consent screen
      redirect(conn, external: url)

    {:ok, details} ->
      # Show consent screen with app details
      render(conn, "consent.html", details: details, auth_id: auth_id)

    {:error, _} ->
      redirect(conn, to: "/")
  end
end

def approve(conn, %{"authorization_id" => auth_id}) do
  session = conn.assigns.session

  case Supabase.Auth.OAuth.approve_authorization(client(), session, auth_id) do
    {:ok, response} -> redirect(conn, external: response.redirect_url)
    {:error, _} -> redirect(conn, to: "/")
  end
end

def deny(conn, %{"authorization_id" => auth_id}) do
  session = conn.assigns.session

  case Supabase.Auth.OAuth.deny_authorization(client(), session, auth_id) do
    {:ok, response} -> redirect(conn, external: response.redirect_url)
    {:error, _} -> redirect(conn, to: "/")
  end
end
```

## LiveView Implementation

For LiveView, handle events instead of controller actions:

```elixir
def mount(%{"authorization_id" => auth_id}, _session, socket) do
  session = socket.assigns.session

  case Supabase.Auth.OAuth.get_authorization_details(client(), session, auth_id) do
    {:ok, %{redirect_url: url}} when not is_nil(url) ->
      {:ok, push_navigate(socket, external: url)}
    {:ok, details} ->
      {:ok, assign(socket, details: details, auth_id: auth_id)}
    {:error, _} ->
      {:ok, push_navigate(socket, to: "/")}
  end
end

def handle_event("approve", _, socket) do
  case Supabase.Auth.OAuth.approve_authorization(
    client(),
    socket.assigns.session,
    socket.assigns.auth_id
  ) do
    {:ok, response} -> {:noreply, push_navigate(socket, external: response.redirect_url)}
    {:error, _} -> {:noreply, socket}
  end
end

def handle_event("deny", _, socket) do
  case Supabase.Auth.OAuth.deny_authorization(
    client(),
    socket.assigns.session,
    socket.assigns.auth_id
  ) do
    {:ok, response} -> {:noreply, push_navigate(socket, external: response.redirect_url)}
    {:error, _} -> {:noreply, socket}
  end
end
```

## Key Concepts

### Authorization Details

The authorization details contain information about the OAuth request:
- Application name and metadata
- Requested scopes
- Whether user previously consented

### Early Exit

When `get_authorization_details/3` returns a `redirect_url`, the user has already consented to the requested scopes. Skip showing the consent screen and redirect immediately.

### Session Requirement

All OAuth operations require a valid authenticated session. Ensure users are logged in before accessing OAuth endpoints.

## Error Handling

Handle errors gracefully by redirecting to safe locations. Avoid exposing error details to prevent information leakage about your OAuth configuration.
