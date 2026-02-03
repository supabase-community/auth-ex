defmodule Supabase.Auth.OAuth.Behaviour do
  @moduledoc """
  Behaviour defining OAuth 2.1 authorization server user-facing operations.

  This behaviour specifies the contract for managing OAuth grants and consent flows.
  """

  alias Supabase.Auth.Session

  @typedoc """
  OAuth client representation.

  ## Fields
    * `:id` - Unique identifier for the OAuth client
    * `:name` - Human-readable name of the client application
    * `:uri` - Client application URI
    * `:logo_uri` - Optional URI to the client's logo
  """
  @type oauth_client :: %{
          id: String.t(),
          name: String.t(),
          uri: String.t(),
          logo_uri: String.t() | nil
        }

  @typedoc """
  OAuth grant representing user authorization to a client.

  ## Fields
    * `:client` - The OAuth client that was granted access
    * `:scopes` - List of scopes that were granted
    * `:granted_at` - ISO8601 timestamp when the grant was created
  """
  @type oauth_grant :: %{
          client: oauth_client(),
          scopes: [String.t()],
          granted_at: String.t()
        }

  @typedoc """
  Authorization request details for consent flow.

  ## Fields
    * `:authorization_id` - Unique identifier for this authorization request
    * `:redirect_url` - If present, user has already consented and should be redirected (early-exit scenario)
    * `:client` - The OAuth client requesting authorization
    * `:user` - User information (id and email)
    * `:scope` - Space-separated string of requested scopes
  """
  @type authorization_details :: %{
          authorization_id: String.t(),
          redirect_url: String.t() | nil,
          client: oauth_client(),
          user: %{id: String.t(), email: String.t()},
          scope: String.t()
        }

  @typedoc """
  Response from consent approval or denial.

  ## Fields
    * `:redirect_url` - URL to redirect the user to complete the OAuth flow
  """
  @type consent_response :: %{
          redirect_url: String.t()
        }

  @doc """
  Lists all OAuth grants for the authenticated user.

  Returns a list of all third-party applications that the user has authorized.
  """
  @callback list_grants(client :: Supabase.Client.t(), session :: Session.t()) ::
              {:ok, [oauth_grant()]} | {:error, term()}

  @doc """
  Revokes an OAuth grant for a specific client.

  Removes authorization for a third-party application.
  """
  @callback revoke_grant(
              client :: Supabase.Client.t(),
              session :: Session.t(),
              client_id :: String.t()
            ) :: :ok | {:error, term()}

  @doc """
  Retrieves authorization details for a consent request.

  Returns information about the OAuth client and requested scopes.
  If the user has already consented, includes a redirect_url for early-exit.
  """
  @callback get_authorization_details(
              client :: Supabase.Client.t(),
              session :: Session.t(),
              authorization_id :: String.t()
            ) :: {:ok, authorization_details()} | {:error, term()}

  @doc """
  Approves an OAuth authorization request.

  Returns a redirect_url to continue the OAuth flow.
  """
  @callback approve_authorization(
              client :: Supabase.Client.t(),
              session :: Session.t(),
              authorization_id :: String.t()
            ) :: {:ok, consent_response()} | {:error, term()}

  @doc """
  Denies an OAuth authorization request.

  Returns a redirect_url to inform the client of the denial.
  """
  @callback deny_authorization(
              client :: Supabase.Client.t(),
              session :: Session.t(),
              authorization_id :: String.t()
            ) :: {:ok, consent_response()} | {:error, term()}
end
