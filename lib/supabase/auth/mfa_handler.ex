defmodule Supabase.Auth.MFAHandler do
  @moduledoc false

  alias Supabase.Auth
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request
  alias Supabase.Fetcher.Response

  @factors_uri "/factors"

  @doc """
  Enrolls a new MFA factor via POST /factors.
  """
  @spec enroll(Client.t(), String.t(), map()) :: {:ok, Response.t()} | {:error, term()}
  def enroll(%Client{} = client, access_token, params) when is_binary(access_token) do
    client
    |> Auth.Request.base(@factors_uri)
    |> Request.with_method(:post)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  @doc """
  Creates a challenge for an MFA factor via POST /factors/{factor_id}/challenge.
  """
  @spec challenge(Client.t(), String.t(), String.t(), map()) ::
          {:ok, Response.t()} | {:error, term()}
  def challenge(%Client{} = client, access_token, factor_id, params)
      when is_binary(access_token) and is_binary(factor_id) do
    client
    |> Auth.Request.base("#{@factors_uri}/#{factor_id}/challenge")
    |> Request.with_method(:post)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_body(params)
    |> Fetcher.request()
  end

  @doc """
  Verifies an MFA challenge via POST /factors/{factor_id}/verify.
  """
  @spec verify(Client.t(), String.t(), String.t(), String.t(), map()) ::
          {:ok, Response.t()} | {:error, term()}
  def verify(%Client{} = client, access_token, factor_id, challenge_id, code_or_webauthn)
      when is_binary(access_token) and is_binary(factor_id) and is_binary(challenge_id) do
    body = Map.merge(%{challenge_id: challenge_id}, code_or_webauthn)

    client
    |> Auth.Request.base("#{@factors_uri}/#{factor_id}/verify")
    |> Request.with_method(:post)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_body(body)
    |> Fetcher.request()
  end

  @doc """
  Unenrolls an MFA factor via DELETE /factors/{factor_id}.
  """
  @spec unenroll(Client.t(), String.t(), String.t()) :: {:ok, Response.t()} | {:error, term()}
  def unenroll(%Client{} = client, access_token, factor_id) when is_binary(access_token) and is_binary(factor_id) do
    client
    |> Auth.Request.base("#{@factors_uri}/#{factor_id}")
    |> Request.with_method(:delete)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Fetcher.request()
  end
end
