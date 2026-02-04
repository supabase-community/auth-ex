defmodule Supabase.Auth.OAuth do
  @moduledoc """
  OAuth 2.1 authorization server APIs for grant management and consent flows.

  Provides functions to manage third-party app access and handle authorization
  consent requests. All operations require an authenticated session.

  ## Grant Management

  List and revoke OAuth grants for authorized applications:

      # List all grants
      {:ok, grants} = OAuth.list_grants(client, session)

      # Revoke access for a specific client
      :ok = OAuth.revoke_grant(client, session, client_id)

  ## Authorization Flow

  Handle OAuth consent requests in three steps:

      # 1. Get authorization details
      {:ok, details} = OAuth.get_authorization_details(client, session, auth_id)

      # 2a. Approve the request
      {:ok, response} = OAuth.approve_authorization(client, session, auth_id)
      # or 2b. Deny the request
      {:ok, response} = OAuth.deny_authorization(client, session, auth_id)

      # 3. Redirect user to response.redirect_url

  If the user previously consented, `get_authorization_details/3` returns a
  `redirect_url` immediately. Check for this to skip the consent screen:

      case OAuth.get_authorization_details(client, session, auth_id) do
        {:ok, %{redirect_url: url}} when not is_nil(url) ->
          # Already consented, redirect immediately
        {:ok, details} ->
          # Show consent screen
      end

  For integration examples, see the OAuth guide in the documentation.
  """

  @behaviour Supabase.Auth.OAuth.Behaviour

  alias Supabase.Auth.OAuthHandler
  alias Supabase.Auth.Schemas.OAuth.AuthorizationDetails
  alias Supabase.Auth.Schemas.OAuth.ConsentResponse
  alias Supabase.Auth.Schemas.OAuth.Grant

  @impl true
  def list_grants(client, session) do
    access_token = session.access_token

    with {:ok, resp} <- OAuthHandler.list_grants(client, access_token) do
      Grant.parse_list(resp.body)
    end
  end

  @impl true
  def revoke_grant(client, session, client_id) do
    access_token = session.access_token

    with {:ok, _} <- OAuthHandler.revoke_grant(client, access_token, client_id), do: :ok
  end

  @impl true
  def get_authorization_details(client, session, authorization_id) do
    access_token = session.access_token

    with {:ok, resp} <-
           OAuthHandler.get_authorization_details(client, access_token, authorization_id) do
      AuthorizationDetails.parse(resp.body)
    end
  end

  @impl true
  def approve_authorization(client, session, authorization_id) do
    access_token = session.access_token

    with {:ok, resp} <-
           OAuthHandler.submit_consent(client, access_token, authorization_id, "approve") do
      ConsentResponse.parse(resp.body)
    end
  end

  @impl true
  def deny_authorization(client, session, authorization_id) do
    access_token = session.access_token

    with {:ok, resp} <-
           OAuthHandler.submit_consent(client, access_token, authorization_id, "deny") do
      ConsentResponse.parse(resp.body)
    end
  end
end
