defmodule Supabase.Auth.OAuth do
  @moduledoc """
  OAuth 2.1 authorization server user-facing APIs.

  This module provides functions for managing OAuth grants and handling
  consent flows in server-side Elixir applications.

  ## Overview

  The OAuth module enables users to:
  - View and revoke third-party app access (grant management)
  - Handle OAuth authorization consent requests (approve/deny flows)

  All operations require an authenticated session with a valid access token.

  ## Usage in Phoenix Controllers

      defmodule MyAppWeb.OAuthController do
        use MyAppWeb, :controller

        alias Supabase.Auth.OAuth

        def grants(conn, _params) do
          session = get_session(conn)

          case OAuth.list_grants(client(), session) do
            {:ok, grants} ->
              render(conn, "grants.html", grants: grants)

            {:error, reason} ->
              conn
              |> put_flash(:error, "Failed to load grants")
              |> redirect(to: "/")
          end
        end

        def revoke(conn, %{"client_id" => client_id}) do
          session = get_session(conn)

          case OAuth.revoke_grant(client(), session, client_id) do
            :ok ->
              conn
              |> put_flash(:info, "Access revoked successfully")
              |> redirect(to: "/oauth/grants")

            {:error, _reason} ->
              conn
              |> put_flash(:error, "Failed to revoke access")
              |> redirect(to: "/oauth/grants")
          end
        end

        def authorize(conn, %{"authorization_id" => auth_id}) do
          session = get_session(conn)

          case OAuth.get_authorization_details(client(), session, auth_id) do
            {:ok, %{redirect_url: url}} when not is_nil(url) ->
              # User already consented, redirect immediately
              redirect(conn, external: url)

            {:ok, details} ->
              # Show consent screen
              render(conn, "consent.html", details: details)

            {:error, _reason} ->
              conn
              |> put_flash(:error, "Invalid authorization request")
              |> redirect(to: "/")
          end
        end

        def approve(conn, %{"authorization_id" => auth_id}) do
          session = get_session(conn)

          case OAuth.approve_authorization(client(), session, auth_id) do
            {:ok, response} ->
              redirect(conn, external: response.redirect_url)

            {:error, _reason} ->
              conn
              |> put_flash(:error, "Failed to approve authorization")
              |> redirect(to: "/")
          end
        end

        def deny(conn, %{"authorization_id" => auth_id}) do
          session = get_session(conn)

          case OAuth.deny_authorization(client(), session, auth_id) do
            {:ok, response} ->
              redirect(conn, external: response.redirect_url)

            {:error, _reason} ->
              conn
              |> put_flash(:error, "Failed to deny authorization")
              |> redirect(to: "/")
          end
        end

        defp client do
          MyApp.Supabase.Client
        end

        defp get_session(conn) do
          # Retrieve session from conn assigns or session store
          conn.assigns.supabase_session
        end
      end

  ## Usage in Phoenix LiveView

      defmodule MyAppWeb.OAuthLive do
        use MyAppWeb, :live_view

        alias Supabase.Auth.OAuth

        def mount(%{"authorization_id" => auth_id}, _session, socket) do
          session = socket.assigns.supabase_session

          case OAuth.get_authorization_details(client(), session, auth_id) do
            {:ok, %{redirect_url: url}} when not is_nil(url) ->
              # User already consented
              {:ok, push_navigate(socket, external: url)}

            {:ok, details} ->
              {:ok, assign(socket, details: details, authorization_id: auth_id)}

            {:error, _reason} ->
              {:ok,
               socket
               |> put_flash(:error, "Invalid authorization request")
               |> push_navigate(to: "/")}
          end
        end

        def handle_event("approve", _params, socket) do
          session = socket.assigns.supabase_session
          auth_id = socket.assigns.authorization_id

          case OAuth.approve_authorization(client(), session, auth_id) do
            {:ok, response} ->
              {:noreply, push_navigate(socket, external: response.redirect_url)}

            {:error, _reason} ->
              {:noreply, put_flash(socket, :error, "Failed to approve authorization")}
          end
        end

        def handle_event("deny", _params, socket) do
          session = socket.assigns.supabase_session
          auth_id = socket.assigns.authorization_id

          case OAuth.deny_authorization(client(), session, auth_id) do
            {:ok, response} ->
              {:noreply, push_navigate(socket, external: response.redirect_url)}

            {:error, _reason} ->
              {:noreply, put_flash(socket, :error, "Failed to deny authorization")}
          end
        end

        defp client, do: MyApp.Supabase.Client
      end

  ## Grant Management

  Users can view all applications they've authorized and revoke access:

      # List all grants
      {:ok, grants} = OAuth.list_grants(client, session)

      Enum.each(grants, fn grant ->
        IO.puts("App: \#{grant.client.name}")
        IO.puts("Scopes: \#{Enum.join(grant.scopes, ", ")}")
        IO.puts("Granted: \#{grant.granted_at}")
      end)

      # Revoke access for a specific client
      client_id = List.first(grants).client.id
      :ok = OAuth.revoke_grant(client, session, client_id)

  ## Authorization Flow

  The OAuth authorization flow involves:

  1. User is redirected to your app with an authorization_id
  2. Fetch authorization details to show consent screen
  3. User approves or denies the request
  4. Redirect user using the provided redirect_url

  ### Early-Exit Scenario

  If the user has already consented to the requested scopes, the API returns
  a `redirect_url` immediately in the authorization details response. Your app
  should check for this and redirect without showing a consent screen:

      case OAuth.get_authorization_details(client, session, auth_id) do
        {:ok, %{redirect_url: url}} when not is_nil(url) ->
          # Already consented, redirect immediately
          redirect(conn, external: url)

        {:ok, details} ->
          # Show consent screen with details
          render_consent_screen(conn, details)
      end
  """

  @behaviour Supabase.Auth.OAuth.Behaviour

  alias Supabase.Auth.OAuthHandler
  alias Supabase.Auth.Schemas.OAuth.AuthorizationDetails
  alias Supabase.Auth.Schemas.OAuth.ConsentResponse
  alias Supabase.Auth.Schemas.OAuth.Grant

  @impl true
  def list_grants(client, session) do
    access_token = session.access_token

    case OAuthHandler.list_grants(client, access_token) do
      {:ok, response} when is_list(response.body) ->
        Grant.parse_list(response.body)

      {:ok, response} ->
        {:error, {:invalid_response, response.body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def revoke_grant(client, session, client_id) do
    access_token = session.access_token

    case OAuthHandler.revoke_grant(client, access_token, client_id) do
      {:ok, _response} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def get_authorization_details(client, session, authorization_id) do
    access_token = session.access_token

    case OAuthHandler.get_authorization_details(client, access_token, authorization_id) do
      {:ok, response} when is_map(response.body) ->
        AuthorizationDetails.parse(response.body)

      {:ok, response} ->
        {:error, {:invalid_response, response.body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def approve_authorization(client, session, authorization_id) do
    access_token = session.access_token

    case OAuthHandler.submit_consent(client, access_token, authorization_id, "approve") do
      {:ok, response} when is_map(response.body) ->
        ConsentResponse.parse(response.body)

      {:ok, response} ->
        {:error, {:invalid_response, response.body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def deny_authorization(client, session, authorization_id) do
    access_token = session.access_token

    case OAuthHandler.submit_consent(client, access_token, authorization_id, "deny") do
      {:ok, response} when is_map(response.body) ->
        ConsentResponse.parse(response.body)

      {:ok, response} ->
        {:error, {:invalid_response, response.body}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
