defmodule Supabase.Auth.Passkey do
  @moduledoc """
  Passkey (first-factor WebAuthn) operations for Supabase Auth.

  Passkeys are an experimental GoTrue feature and must be enabled
  server-side on your project.

  This module covers only the HTTP half of the WebAuthn flow: fetching
  challenge options from the server and verifying the resulting credential.
  The WebAuthn ceremony itself (`navigator.credentials.create/get`) runs in
  the browser and is wired by your application, typically through a
  LiveView plus a JavaScript hook. See `pages/passkey_guide.md` for a
  complete recipe.

  ## Typical flow

  1. `start_registration/2` (or `start_authentication/2` for sign-in)
     fetches the server's WebAuthn options and a `challenge_id`.
  2. Your app hands the `options` map to a browser JS hook, which runs the
     `navigator.credentials` ceremony.
  3. The hook returns the serialized credential; your app calls
     `verify_registration/4` (or `verify_authentication/3`), passing the
     credential through verbatim.

  ## Related Modules

  - `Supabase.Auth.Passkey.Behaviour` - type definitions for passkey operations
  - `Supabase.Auth.MFA` - MFA operations, including WebAuthn as a second factor
  """

  @behaviour Supabase.Auth.Passkey.Behaviour

  alias Supabase.Auth.Passkey.Behaviour, as: PasskeyBehaviour
  alias Supabase.Auth.PasskeyHandler
  alias Supabase.Auth.Schemas.Passkey.StartAuthenticationParams
  alias Supabase.Auth.Schemas.Passkey.UpdateParams
  alias Supabase.Auth.Schemas.Passkey.VerifyParams
  alias Supabase.Auth.Session
  alias Supabase.Client

  @doc """
  Gets WebAuthn registration options for the authenticated user.

  The returned `options` map must be passed to the browser ceremony; see
  the passkey guide for a LiveView + JS hook recipe.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token

  ## Returns

  * `{:ok, options}` - Map with `challenge_id`, `options` (WebAuthn
    creation options, passthrough) and optional `expires_at`
  * `{:error, error}` - Request failed
  """
  @impl true
  @spec start_registration(Client.t(), Session.t()) ::
          {:ok, PasskeyBehaviour.creation_options()} | {:error, term()}
  def start_registration(%Client{} = client, %Session{} = session) do
    with {:ok, response} <- PasskeyHandler.start_registration(client, session.access_token) do
      parse_options(response.body)
    end
  end

  @doc """
  Verifies a passkey registration with the browser credential.

  The `credential` map is the serialized WebAuthn credential
  (`RegistrationResponseJSON`) and is sent through verbatim.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token
  * `challenge_id` - The challenge id from `start_registration/2`
  * `credential` - The browser credential map

  ## Returns

  * `{:ok, passkey}` - The registered passkey
  * `{:error, error}` - Verification failed
  """
  @impl true
  @spec verify_registration(Client.t(), Session.t(), String.t(), PasskeyBehaviour.credential()) ::
          {:ok, PasskeyBehaviour.passkey()} | {:error, term()}
  def verify_registration(%Client{} = client, %Session{} = session, challenge_id, credential)
      when is_binary(challenge_id) and is_map(credential) do
    with {:ok, params} <- VerifyParams.parse(%{challenge_id: challenge_id, credential: credential}),
         {:ok, response} <- PasskeyHandler.verify_registration(client, session.access_token, params) do
      parse(response.body)
    end
  end

  @doc """
  Gets WebAuthn authentication options for sign-in with a passkey.

  Does not require an authenticated session. When the project has captcha
  enabled, pass `%{captcha_token: "..."}`.

  ## Parameters

  * `client` - The Supabase client
  * `opts` - Optional map with `captcha_token`

  ## Returns

  * `{:ok, options}` - Map with `challenge_id`, `options` (WebAuthn request
    options, passthrough) and optional `expires_at`
  * `{:error, error}` - Request failed
  """
  @impl true
  @spec start_authentication(Client.t(), map()) ::
          {:ok, PasskeyBehaviour.request_options()} | {:error, term()}
  def start_authentication(%Client{} = client, opts \\ %{}) do
    with {:ok, body} <- StartAuthenticationParams.to_request(Map.new(opts)),
         {:ok, response} <- PasskeyHandler.start_authentication(client, body) do
      parse_options(response.body)
    end
  end

  @doc """
  Verifies a passkey sign-in with the browser credential.

  Does not require an authenticated session. On success returns a fresh
  `Supabase.Auth.Session` for the user.

  ## Parameters

  * `client` - The Supabase client
  * `challenge_id` - The challenge id from `start_authentication/2`
  * `credential` - The browser credential map (sent through verbatim)

  ## Returns

  * `{:ok, session}` - The authenticated session
  * `{:error, error}` - Verification failed
  """
  @impl true
  @spec verify_authentication(Client.t(), String.t(), PasskeyBehaviour.credential()) ::
          {:ok, Session.t()} | {:error, term()}
  def verify_authentication(%Client{} = client, challenge_id, credential)
      when is_binary(challenge_id) and is_map(credential) do
    with {:ok, params} <- VerifyParams.parse(%{challenge_id: challenge_id, credential: credential}),
         {:ok, response} <- PasskeyHandler.verify_authentication(client, params) do
      Session.parse(response.body)
    end
  end

  @doc """
  Lists the authenticated user's passkeys.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token

  ## Returns

  * `{:ok, passkeys}` - List of passkey maps
  * `{:error, error}` - Request failed
  """
  @impl true
  @spec list(Client.t(), Session.t()) ::
          {:ok, [PasskeyBehaviour.passkey()]} | {:error, term()}
  def list(%Client{} = client, %Session{} = session) do
    with {:ok, response} <- PasskeyHandler.list(client, session.access_token) do
      parse_list(response.body)
    end
  end

  @doc """
  Renames a passkey.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token
  * `passkey_id` - The passkey to rename
  * `friendly_name` - The new friendly name (max 120 characters)

  ## Returns

  * `{:ok, passkey}` - The updated passkey
  * `{:error, error}` - Update failed
  """
  @impl true
  @spec update(Client.t(), Session.t(), String.t(), String.t()) ::
          {:ok, PasskeyBehaviour.passkey()} | {:error, term()}
  def update(%Client{} = client, %Session{} = session, passkey_id, friendly_name)
      when is_binary(passkey_id) and is_binary(friendly_name) do
    with {:ok, params} <- UpdateParams.parse(%{friendly_name: friendly_name}),
         {:ok, response} <- PasskeyHandler.update(client, session.access_token, passkey_id, params) do
      parse(response.body)
    end
  end

  @doc """
  Removes a passkey from the authenticated user's account.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token
  * `passkey_id` - The passkey to delete

  ## Returns

  * `:ok` - Passkey deleted
  * `{:error, error}` - Deletion failed
  """
  @impl true
  @spec delete(Client.t(), Session.t(), String.t()) :: :ok | {:error, term()}
  def delete(%Client{} = client, %Session{} = session, passkey_id) when is_binary(passkey_id) do
    with {:ok, _response} <- PasskeyHandler.delete(client, session.access_token, passkey_id),
         do: :ok
  end

  @doc false
  @spec parse(map()) :: {:ok, PasskeyBehaviour.passkey()} | {:error, :invalid_passkey_response}
  def parse(%{"id" => id} = data) do
    {:ok,
     %{
       id: id,
       friendly_name: data["friendly_name"],
       created_at: data["created_at"],
       last_used_at: data["last_used_at"]
     }}
  end

  def parse(_), do: {:error, :invalid_passkey_response}

  @doc false
  @spec parse_list(list()) :: {:ok, [PasskeyBehaviour.passkey()]} | {:error, term()}
  def parse_list(items) when is_list(items) do
    items
    |> Enum.reduce_while({:ok, []}, fn attrs, {:ok, acc} ->
      case parse(attrs) do
        {:ok, passkey} -> {:cont, {:ok, [passkey | acc]}}
        {:error, _reason} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, passkeys} -> {:ok, Enum.reverse(passkeys)}
      err -> err
    end
  end

  def parse_list(_), do: {:error, :invalid_passkey_response}

  defp parse_options(%{"challenge_id" => challenge_id, "options" => options} = data) do
    {:ok, %{challenge_id: challenge_id, options: options, expires_at: data["expires_at"]}}
  end

  defp parse_options(_), do: {:error, :invalid_passkey_options_response}
end
