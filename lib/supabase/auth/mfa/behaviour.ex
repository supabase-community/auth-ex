defmodule Supabase.Auth.MFA.Behaviour do
  @moduledoc """
  Behaviour for MFA operations with type definitions.

  This module defines all type specifications for Multi-Factor Authentication
  operations including factors, challenges, verification responses, and
  authenticator assurance levels.

  ## Factor Types

  Three types of MFA factors are supported:

  - **TOTP** (`:totp`) - Time-based One-Time Password using authenticator apps
  - **Phone** (`:phone`) - SMS or WhatsApp-based verification
  - **WebAuthn** (`:webauthn`) - Hardware security keys and biometric authentication

  ## Type Hierarchy

  All factor types share common fields (id, friendly_name, status, timestamps)
  but have type-specific additional fields:

  - `totp_factor/0` includes `totp` field with QR code, secret, and URI
  - `phone_factor/0` includes `phone` field with E.164 formatted number
  - `webauthn_factor/0` has no additional type-specific fields

  The `factor/0` type is a union of all three specific factor types.
  """

  alias Supabase.Auth.Session
  alias Supabase.Client

  @type factor_type :: :totp | :phone | :webauthn
  @type factor_status :: :verified | :unverified

  @type totp_data :: %{
          qr_code: String.t(),
          secret: String.t(),
          uri: String.t()
        }

  @type factor_base :: %{
          id: String.t(),
          friendly_name: String.t() | nil,
          factor_type: factor_type(),
          status: factor_status(),
          created_at: String.t(),
          updated_at: String.t(),
          last_challenged_at: String.t() | nil
        }

  @type totp_factor :: %{
          id: String.t(),
          friendly_name: String.t() | nil,
          factor_type: :totp,
          status: factor_status(),
          totp: totp_data(),
          created_at: String.t(),
          updated_at: String.t(),
          last_challenged_at: String.t() | nil
        }

  @type phone_factor :: %{
          id: String.t(),
          friendly_name: String.t() | nil,
          factor_type: :phone,
          status: factor_status(),
          phone: String.t(),
          created_at: String.t(),
          updated_at: String.t(),
          last_challenged_at: String.t() | nil
        }

  @type webauthn_factor :: %{
          id: String.t(),
          friendly_name: String.t() | nil,
          factor_type: :webauthn,
          status: factor_status(),
          created_at: String.t(),
          updated_at: String.t(),
          last_challenged_at: String.t() | nil
        }

  @type factor :: totp_factor() | phone_factor() | webauthn_factor()

  @type enroll_response :: totp_factor() | phone_factor() | webauthn_factor()

  @type challenge_response :: %{
          id: String.t(),
          type: factor_type(),
          expires_at: integer()
        }

  @type webauthn_challenge_response :: %{
          id: String.t(),
          type: :webauthn,
          expires_at: integer(),
          webauthn: %{
            type: String.t(),
            credential_options: map()
          }
        }

  @type aal_level :: :aal1 | :aal2
  @type aal_response :: %{
          current_level: aal_level() | nil,
          next_level: aal_level() | nil,
          current_authentication_methods: [String.t()]
        }

  @type factors_list :: %{
          all: [factor()],
          totp: [totp_factor()],
          phone: [phone_factor()],
          webauthn: [webauthn_factor()]
        }

  @callback enroll(Client.t(), Session.t(), map()) ::
              {:ok, enroll_response()} | {:error, term()}
  @callback challenge(Client.t(), Session.t(), String.t(), map()) ::
              {:ok, challenge_response() | webauthn_challenge_response()} | {:error, term()}
  @callback verify(Client.t(), Session.t(), String.t(), String.t(), map()) ::
              {:ok, Session.t()} | {:error, term()}
  @callback unenroll(Client.t(), Session.t(), String.t()) ::
              {:ok, %{id: String.t()}} | {:error, term()}
  @callback challenge_and_verify(Client.t(), Session.t(), String.t(), String.t()) ::
              {:ok, Session.t()} | {:error, term()}
  @callback list_factors(Client.t(), Session.t()) ::
              {:ok, factors_list()} | {:error, term()}
  @callback get_authenticator_assurance_level(Client.t(), Session.t()) ::
              {:ok, aal_response()} | {:error, term()}
end
