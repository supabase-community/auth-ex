defmodule Supabase.Auth.Passkey.Behaviour do
  @moduledoc """
  Behaviour and type definitions for passkey (first-factor WebAuthn) operations.

  The WebAuthn ceremony itself (`navigator.credentials.create/get`) runs in
  the browser; these callbacks cover the HTTP half: fetching challenge
  options and verifying the resulting credential. See the passkey guide
  (`pages/passkey_guide.md`) for wiring the ceremony via LiveView + JS hooks.
  """

  alias Supabase.Auth.Session
  alias Supabase.Client

  @type credential :: map()

  @type creation_options :: %{
          required(:challenge_id) => String.t(),
          required(:options) => map(),
          optional(:expires_at) => integer() | nil
        }

  @type request_options :: %{
          required(:challenge_id) => String.t(),
          required(:options) => map(),
          optional(:expires_at) => integer() | nil
        }

  @type passkey :: %{
          required(:id) => String.t(),
          optional(:friendly_name) => String.t() | nil,
          optional(:created_at) => String.t() | nil,
          optional(:last_used_at) => String.t() | nil
        }

  @callback start_registration(Client.t(), Session.t()) ::
              {:ok, creation_options()} | {:error, term()}

  @callback verify_registration(Client.t(), Session.t(), String.t(), credential()) ::
              {:ok, passkey()} | {:error, term()}

  @callback start_authentication(Client.t(), map()) ::
              {:ok, request_options()} | {:error, term()}

  @callback verify_authentication(Client.t(), String.t(), credential()) ::
              {:ok, Session.t()} | {:error, term()}

  @callback list(Client.t(), Session.t()) ::
              {:ok, [passkey()]} | {:error, term()}

  @callback update(Client.t(), Session.t(), String.t(), String.t()) ::
              {:ok, passkey()} | {:error, term()}

  @callback delete(Client.t(), Session.t(), String.t()) :: :ok | {:error, term()}
end
