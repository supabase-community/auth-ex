defmodule Supabase.Auth.PasskeyHandler do
  @moduledoc false

  alias Supabase.Auth
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request
  alias Supabase.Fetcher.Response

  @registration_options_uri "/passkeys/registration/options"
  @registration_verify_uri "/passkeys/registration/verify"
  @authentication_options_uri "/passkeys/authentication/options"
  @authentication_verify_uri "/passkeys/authentication/verify"
  @passkeys_uri "/passkeys"

  defp passkey_endpoint(passkey_id), do: @passkeys_uri <> "/#{passkey_id}"

  defp auth_header(access_token), do: %{"authorization" => "Bearer #{access_token}"}

  @doc """
  Gets WebAuthn registration options via POST /passkeys/registration/options.
  """
  @spec start_registration(Client.t(), String.t()) :: {:ok, Response.t()} | {:error, term()}
  def start_registration(%Client{} = client, access_token) when is_binary(access_token) do
    client
    |> Auth.Request.base(@registration_options_uri)
    |> Request.with_method(:post)
    |> Request.with_headers(auth_header(access_token))
    |> Request.with_body(%{})
    |> Fetcher.request()
  end

  @doc """
  Verifies a passkey registration via POST /passkeys/registration/verify.
  """
  @spec verify_registration(Client.t(), String.t(), map()) ::
          {:ok, Response.t()} | {:error, term()}
  def verify_registration(%Client{} = client, access_token, params) when is_binary(access_token) and is_map(params) do
    body = %{challenge_id: params.challenge_id, credential: params.credential}

    client
    |> Auth.Request.base(@registration_verify_uri)
    |> Request.with_method(:post)
    |> Request.with_headers(auth_header(access_token))
    |> Request.with_body(body)
    |> Fetcher.request()
  end

  @doc """
  Gets WebAuthn authentication options via POST /passkeys/authentication/options.
  """
  @spec start_authentication(Client.t(), map()) :: {:ok, Response.t()} | {:error, term()}
  def start_authentication(%Client{} = client, body) when is_map(body) do
    client
    |> Auth.Request.base(@authentication_options_uri)
    |> Request.with_method(:post)
    |> Request.with_body(body)
    |> Fetcher.request()
  end

  @doc """
  Verifies a passkey authentication via POST /passkeys/authentication/verify.
  """
  @spec verify_authentication(Client.t(), map()) :: {:ok, Response.t()} | {:error, term()}
  def verify_authentication(%Client{} = client, params) when is_map(params) do
    body = %{challenge_id: params.challenge_id, credential: params.credential}

    client
    |> Auth.Request.base(@authentication_verify_uri)
    |> Request.with_method(:post)
    |> Request.with_body(body)
    |> Fetcher.request()
  end

  @doc """
  Lists the user's passkeys via GET /passkeys.
  """
  @spec list(Client.t(), String.t()) :: {:ok, Response.t()} | {:error, term()}
  def list(%Client{} = client, access_token) when is_binary(access_token) do
    client
    |> Auth.Request.base(@passkeys_uri)
    |> Request.with_method(:get)
    |> Request.with_headers(auth_header(access_token))
    |> Fetcher.request()
  end

  @doc """
  Renames a passkey via PATCH /passkeys/{passkey_id}.
  """
  @spec update(Client.t(), String.t(), String.t(), map()) ::
          {:ok, Response.t()} | {:error, term()}
  def update(%Client{} = client, access_token, passkey_id, params)
      when is_binary(access_token) and is_binary(passkey_id) and is_map(params) do
    body = %{friendly_name: params.friendly_name}

    client
    |> Auth.Request.base(passkey_endpoint(passkey_id))
    |> Request.with_method(:patch)
    |> Request.with_headers(auth_header(access_token))
    |> Request.with_body(body)
    |> Fetcher.request()
  end

  @doc """
  Deletes a passkey via DELETE /passkeys/{passkey_id}.
  """
  @spec delete(Client.t(), String.t(), String.t()) :: {:ok, Response.t()} | {:error, term()}
  def delete(%Client{} = client, access_token, passkey_id) when is_binary(access_token) and is_binary(passkey_id) do
    client
    |> Auth.Request.base(passkey_endpoint(passkey_id))
    |> Request.with_method(:delete)
    |> Request.with_headers(auth_header(access_token))
    |> Fetcher.request()
  end
end
