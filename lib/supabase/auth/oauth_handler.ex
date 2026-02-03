defmodule Supabase.Auth.OAuthHandler do
  @moduledoc false
  # Private HTTP handler for OAuth 2.1 authorization server operations.

  alias Supabase.Auth
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request

  @grants_uri "/user/oauth/grants"
  @authorizations_uri "/oauth/authorizations"

  @doc """
  Lists all OAuth grants for the authenticated user.
  """
  @spec list_grants(Supabase.Client.t(), String.t()) :: {:ok, term()} | {:error, term()}
  def list_grants(client, access_token) do
    client
    |> Auth.Request.base(@grants_uri)
    |> Request.with_method(:get)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Fetcher.request()
  end

  @doc """
  Revokes an OAuth grant for a specific client.
  """
  @spec revoke_grant(Supabase.Client.t(), String.t(), String.t()) ::
          {:ok, term()} | {:error, term()}
  def revoke_grant(client, access_token, client_id) do
    client
    |> Auth.Request.base(@grants_uri)
    |> Request.with_method(:delete)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_query(%{client_id: client_id})
    |> Fetcher.request()
  end

  @doc """
  Retrieves authorization details for a consent request.
  """
  @spec get_authorization_details(Supabase.Client.t(), String.t(), String.t()) ::
          {:ok, term()} | {:error, term()}
  def get_authorization_details(client, access_token, authorization_id) do
    uri = "#{@authorizations_uri}/#{authorization_id}"

    client
    |> Auth.Request.base(uri)
    |> Request.with_method(:get)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Fetcher.request()
  end

  @doc """
  Submits consent for an authorization request (approve or deny).
  """
  @spec submit_consent(Supabase.Client.t(), String.t(), String.t(), String.t()) ::
          {:ok, term()} | {:error, term()}
  def submit_consent(client, access_token, authorization_id, action) when action in ["approve", "deny"] do
    uri = "#{@authorizations_uri}/#{authorization_id}/consent"

    client
    |> Auth.Request.base(uri)
    |> Request.with_method(:post)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_body(%{action: action})
    |> Fetcher.request()
  end
end
