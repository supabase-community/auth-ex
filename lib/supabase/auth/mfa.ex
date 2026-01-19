defmodule Supabase.Auth.MFA do
  @moduledoc """
  Multi-Factor Authentication (MFA) operations for Supabase Auth.

  This module provides functions to manage MFA factors including TOTP (Time-based One-Time Password),
  Phone (SMS/WhatsApp), and WebAuthn authentication methods.

  ## Factor Types

  - **TOTP**: Time-based one-time passwords (authenticator apps like Google Authenticator, Authy)
  - **Phone**: SMS or WhatsApp-based verification codes
  - **WebAuthn**: Hardware security keys and biometric authentication

  ## Typical MFA Flow

  1. **Enroll**: User enrolls a new MFA factor using `enroll/3`
  2. **Challenge**: System issues a challenge for verification using `challenge/4`
  3. **Verify**: User provides response to complete verification using `verify/5`

  Alternatively, for TOTP factors, you can use `challenge_and_verify/4` to combine steps 2 and 3.

  ## Authenticator Assurance Levels (AAL)

  - **AAL1**: Single-factor authentication (password, magic link, OAuth)
  - **AAL2**: Multi-factor authentication (at least one MFA factor verified)

  After successful MFA verification, the session will be upgraded to AAL2.

  ## Examples

      # Enroll TOTP factor
      {:ok, factor} = Supabase.Auth.MFA.enroll(client, session, %{
        factor_type: :totp,
        friendly_name: "My Authenticator"
      })

      # Display QR code to user (factor.totp.qr_code contains SVG data)
      qr_code_svg = factor.totp.qr_code

      # Enroll Phone factor
      {:ok, phone_factor} = Supabase.Auth.MFA.enroll(client, session, %{
        factor_type: :phone,
        phone: "+1234567890",
        friendly_name: "My Phone"
      })

      # Challenge and verify in one step (TOTP only)
      {:ok, new_session} = Supabase.Auth.MFA.challenge_and_verify(
        client,
        session,
        factor.id,
        "123456"
      )

      # Or use separate challenge and verify steps
      {:ok, challenge} = Supabase.Auth.MFA.challenge(client, session, factor.id, %{})
      {:ok, new_session} = Supabase.Auth.MFA.verify(
        client,
        session,
        factor.id,
        challenge.id,
        %{code: "123456"}
      )

      # List all factors
      {:ok, %{all: factors, totp: totp_factors}} = Supabase.Auth.MFA.list_factors(client, session)

      # Get current authentication level
      {:ok, %{current_level: :aal2}} =
        Supabase.Auth.MFA.get_authenticator_assurance_level(client, session)

      # Unenroll a factor
      {:ok, %{id: factor_id}} = Supabase.Auth.MFA.unenroll(client, session, factor.id)

  ## Related Modules

  - `Supabase.Auth.MFA.Behaviour` - Type definitions for MFA operations
  - `Supabase.Auth.Session` - Session containing access tokens
  - `Supabase.Auth.User` - User profile with factors
  """

  @behaviour Supabase.Auth.MFA.Behaviour

  alias Supabase.Auth.MFA.Behaviour, as: MFABehaviour
  alias Supabase.Auth.MFAHandler
  alias Supabase.Auth.Schemas.MFA.ChallengeAndVerifyParams
  alias Supabase.Auth.Schemas.MFA.ChallengeParams
  alias Supabase.Auth.Schemas.MFA.EnrollParams
  alias Supabase.Auth.Schemas.MFA.VerifyParams
  alias Supabase.Auth.Session
  alias Supabase.Auth.User
  alias Supabase.Client

  @doc """
  Enrolls a new MFA factor for the authenticated user.

  The enrollment process differs based on the factor type:
  - **TOTP**: Returns QR code, secret, and URI for scanning into authenticator apps
  - **Phone**: Returns the enrolled phone number
  - **WebAuthn**: Returns the factor ID for WebAuthn credential registration

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session containing access token
  * `params` - Factor enrollment parameters (map with factor_type and type-specific fields):
    * For TOTP: `%{factor_type: :totp, friendly_name: "...", issuer: "..."}`
    * For Phone: `%{factor_type: :phone, phone: "+1234567890", friendly_name: "..."}`
    * For WebAuthn: `%{factor_type: :webauthn, friendly_name: "..."}`

  ## Returns

  * `{:ok, factor}` - Successfully enrolled factor with type-specific data:
    * TOTP: includes `totp` field with `qr_code`, `secret`, and `uri`
    * Phone: includes `phone` field with E.164 formatted number
    * WebAuthn: basic factor information only
  * `{:error, error}` - Enrollment failed

  ## Examples

      # Enroll TOTP factor
      iex> Supabase.Auth.MFA.enroll(client, session, %{
      ...>   factor_type: :totp,
      ...>   friendly_name: "My Authenticator"
      ...> })
      {:ok, %{
        id: "factor-uuid",
        factor_type: :totp,
        friendly_name: "My Authenticator",
        status: :unverified,
        totp: %{
          qr_code: "data:image/svg+xml;utf-8,...",
          secret: "SECRET123",
          uri: "otpauth://totp/..."
        }
      }}

      # Enroll Phone factor
      iex> Supabase.Auth.MFA.enroll(client, session, %{
      ...>   factor_type: :phone,
      ...>   phone: "+1234567890"
      ...> })
      {:ok, %{
        id: "factor-uuid",
        factor_type: :phone,
        status: :unverified,
        phone: "+1234567890"
      }}

  """
  @spec enroll(Client.t(), Session.t(), map()) ::
          {:ok, MFABehaviour.enroll_response()} | {:error, term()}
  def enroll(%Client{} = client, %Session{} = session, %{factor_type: _} = params) do
    with {:ok, validated_params} <- EnrollParams.parse(params),
         {:ok, response} <- MFAHandler.enroll(client, session.access_token, validated_params) do
      parse_factor(response.body)
    end
  end

  @doc """
  Creates a challenge for an MFA factor.

  The challenge must be verified using `verify/5` with the appropriate response.
  Different factor types require different challenge parameters:
  - **TOTP**: No additional parameters needed (empty map)
  - **Phone**: Requires `channel` (`:sms` or `:whatsapp`)
  - **WebAuthn**: Requires `webauthn` map with `rp_id` and optional `rp_origins`

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session
  * `factor_id` - ID of the factor to challenge
  * `params` - Challenge parameters (type-specific):
    * For TOTP: `%{}` (empty map)
    * For Phone: `%{channel: :sms}` or `%{channel: :whatsapp}`
    * For WebAuthn: `%{webauthn: %{rp_id: "example.com", rp_origins: ["https://example.com"]}}`

  ## Returns

  * `{:ok, challenge}` - Challenge created with:
    * `id` - Challenge ID for verification
    * `type` - Factor type
    * `expires_at` - Unix timestamp when challenge expires
    * `webauthn` - WebAuthn credential options (WebAuthn only)
  * `{:error, error}` - Challenge creation failed

  ## Examples

      # TOTP challenge
      iex> Supabase.Auth.MFA.challenge(client, session, totp_factor_id, %{})
      {:ok, %{id: "challenge-id", type: :totp, expires_at: 1234567890}}

      # Phone challenge via SMS
      iex> Supabase.Auth.MFA.challenge(client, session, phone_factor_id, %{channel: :sms})
      {:ok, %{id: "challenge-id", type: :phone, expires_at: 1234567890}}

      # WebAuthn challenge
      iex> Supabase.Auth.MFA.challenge(client, session, webauthn_factor_id, %{
      ...>   webauthn: %{rp_id: "example.com"}
      ...> })
      {:ok, %{
        id: "challenge-id",
        type: :webauthn,
        expires_at: 1234567890,
        webauthn: %{type: "create", credential_options: %{...}}
      }}

  """
  @spec challenge(Client.t(), Session.t(), String.t(), map()) ::
          {:ok, MFABehaviour.challenge_response() | MFABehaviour.webauthn_challenge_response()}
          | {:error, term()}
  def challenge(%Client{} = client, %Session{} = session, factor_id, params) when is_binary(factor_id) do
    with {:ok, validated_params} <- ChallengeParams.parse(params),
         {:ok, response} <-
           MFAHandler.challenge(client, session.access_token, factor_id, validated_params) do
      parse_challenge_response(response.body)
    end
  end

  @doc """
  Verifies an MFA challenge with the user's response.

  Returns a new session with elevated authentication assurance level (AAL2).
  The verification parameters differ based on factor type:
  - **TOTP/Phone**: Provide the 6-digit code
  - **WebAuthn**: Provide the WebAuthn credential response

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session
  * `factor_id` - ID of the challenged factor
  * `challenge_id` - ID of the challenge to verify
  * `params` - Verification parameters (type-specific):
    * For TOTP/Phone: `%{code: "123456"}`
    * For WebAuthn: `%{webauthn: %{type: "...", rp_id: "...", credential_response: {...}}}`

  ## Returns

  * `{:ok, session}` - New session with AAL2 authentication including:
    * `access_token` - New JWT token with elevated AAL
    * `refresh_token` - New refresh token
    * `user` - Updated user object
    * `expires_in` - Token expiration time
  * `{:error, error}` - Verification failed (invalid code, expired challenge, etc.)

  ## Examples

      # Verify TOTP code
      iex> Supabase.Auth.MFA.verify(client, session, factor_id, challenge_id, %{code: "123456"})
      {:ok, %Supabase.Auth.Session{
        access_token: "eyJhbGci...",
        user: %Supabase.Auth.User{...}
      }}

      # Verify Phone code
      iex> Supabase.Auth.MFA.verify(client, session, factor_id, challenge_id, %{code: "654321"})
      {:ok, %Supabase.Auth.Session{...}}

      # Verify WebAuthn credential
      iex> Supabase.Auth.MFA.verify(client, session, factor_id, challenge_id, %{
      ...>   webauthn: %{
      ...>     type: "create",
      ...>     rp_id: "example.com",
      ...>     credential_response: credential
      ...>   }
      ...> })
      {:ok, %Supabase.Auth.Session{...}}

  """
  @spec verify(Client.t(), Session.t(), String.t(), String.t(), map()) ::
          {:ok, Session.t()} | {:error, term()}
  def verify(%Client{} = client, %Session{} = session, factor_id, challenge_id, params)
      when is_binary(factor_id) and is_binary(challenge_id) do
    with {:ok, validated_params} <- VerifyParams.parse(params),
         {:ok, response} <-
           MFAHandler.verify(
             client,
             session.access_token,
             factor_id,
             challenge_id,
             validated_params
           ) do
      Session.parse(response.body)
    end
  end

  @doc """
  Removes an MFA factor from the user's account.

  The factor must be verified before it can be unenrolled. This operation
  removes the factor permanently and cannot be undone.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session
  * `factor_id` - ID of the factor to remove

  ## Returns

  * `{:ok, %{id: factor_id}}` - Factor successfully removed
  * `{:error, error}` - Unenrollment failed

  ## Examples

      iex> Supabase.Auth.MFA.unenroll(client, session, "factor-uuid")
      {:ok, %{id: "factor-uuid"}}

  """
  @spec unenroll(Client.t(), Session.t(), String.t()) ::
          {:ok, %{id: String.t()}} | {:error, term()}
  def unenroll(%Client{} = client, %Session{} = session, factor_id) when is_binary(factor_id) do
    with {:ok, response} <- MFAHandler.unenroll(client, session.access_token, factor_id) do
      {:ok, %{id: response.body["id"]}}
    end
  end

  @doc """
  Combines challenge and verify operations in a single call (TOTP only).

  This is a convenience function for TOTP factors where the code is immediately
  available from the user's authenticator app. It internally creates a challenge
  and immediately verifies it with the provided code.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session
  * `factor_id` - ID of the TOTP factor
  * `code` - The 6-digit TOTP code from the authenticator app

  ## Returns

  * `{:ok, session}` - New session with AAL2 authentication
  * `{:error, error}` - Verification failed

  ## Examples

      iex> Supabase.Auth.MFA.challenge_and_verify(client, session, factor_id, "123456")
      {:ok, %Supabase.Auth.Session{...}}

  ## Note

  This function only works with TOTP factors. For Phone or WebAuthn factors,
  use separate `challenge/4` and `verify/5` calls to handle the asynchronous
  nature of those verification methods.
  """
  @spec challenge_and_verify(Client.t(), Session.t(), String.t(), String.t()) ::
          {:ok, Session.t()} | {:error, term()}
  def challenge_and_verify(%Client{} = client, %Session{} = session, factor_id, code)
      when is_binary(factor_id) and is_binary(code) do
    with {:ok, _validated} <- ChallengeAndVerifyParams.parse(%{code: code}),
         {:ok, challenge_response} <- challenge(client, session, factor_id, %{}) do
      verify(client, session, factor_id, challenge_response.id, %{code: code})
    end
  end

  @doc """
  Lists all MFA factors for the authenticated user.

  Returns factors organized by type for easy filtering. Only verified factors
  are included in the type-specific lists (`:totp`, `:phone`, `:webauthn`),
  while the `:all` list includes both verified and unverified factors.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session

  ## Returns

  * `{:ok, factors_map}` - Map with keys:
    * `:all` - All factors (verified and unverified)
    * `:totp` - Verified TOTP factors only
    * `:phone` - Verified Phone factors only
    * `:webauthn` - Verified WebAuthn factors only
  * `{:error, error}` - Failed to retrieve factors

  ## Examples

      iex> {:ok, factors} = Supabase.Auth.MFA.list_factors(client, session)
      iex> length(factors.all)
      3
      iex> length(factors.totp)
      2
      iex> Enum.map(factors.totp, & &1.friendly_name)
      ["My Phone", "Work Authenticator"]

  """
  @spec list_factors(Client.t(), Session.t()) ::
          {:ok, MFABehaviour.factors_list()} | {:error, term()}
  def list_factors(%Client{} = _client, %Session{} = session) do
    factors = session.user.factors || []

    parsed_factors =
      factors
      |> Enum.map(&parse_factor_from_user/1)
      |> Enum.filter(&match?({:ok, _}, &1))
      |> Enum.map(fn {:ok, factor} -> factor end)

    totp_factors =
      Enum.filter(parsed_factors, fn f ->
        f.factor_type == :totp and f.status == :verified
      end)

    phone_factors =
      Enum.filter(parsed_factors, fn f ->
        f.factor_type == :phone and f.status == :verified
      end)

    webauthn_factors =
      Enum.filter(parsed_factors, fn f ->
        f.factor_type == :webauthn and f.status == :verified
      end)

    {:ok,
     %{
       all: parsed_factors,
       totp: totp_factors,
       phone: phone_factors,
       webauthn: webauthn_factors
     }}
  end

  @doc """
  Gets the current and next possible authenticator assurance levels.

  AAL (Authenticator Assurance Level) indicates the strength of authentication:
  - **AAL1**: Single-factor authentication (password, magic link, OAuth)
  - **AAL2**: Multi-factor authentication (at least one verified MFA factor)

  This function extracts AAL information from the session's JWT claims without
  making an API call. It also determines the next achievable AAL based on the
  user's enrolled factors.

  ## Parameters

  * `client` - The Supabase client
  * `session` - Active user session

  ## Returns

  * `{:ok, aal_info}` - Map with:
    * `:current_level` - Current AAL (`:aal1`, `:aal2`, or `nil`)
    * `:next_level` - Next achievable AAL (`:aal1`, `:aal2`, or `nil`)
    * `:current_authentication_methods` - List of authentication method references from JWT `amr` claim
  * `{:error, error}` - Failed to parse AAL information

  ## Examples

      # User with password authentication only (no MFA)
      iex> Supabase.Auth.MFA.get_authenticator_assurance_level(client, session)
      {:ok, %{
        current_level: :aal1,
        next_level: :aal2,
        current_authentication_methods: ["password"]
      }}

      # User with verified MFA factor
      iex> Supabase.Auth.MFA.get_authenticator_assurance_level(client, session_after_mfa)
      {:ok, %{
        current_level: :aal2,
        next_level: :aal2,
        current_authentication_methods: ["password", "totp"]
      }}

  ## Note

  This function does not make an HTTP request. It decodes the JWT token from
  the session to extract AAL claims.
  """
  @spec get_authenticator_assurance_level(Client.t(), Session.t()) ::
          {:ok, MFABehaviour.aal_response()} | {:error, term()}
  def get_authenticator_assurance_level(%Client{} = _client, %Session{} = session) do
    with {:ok, claims} <- decode_jwt_claims(session.access_token) do
      current_level = parse_aal_level(claims["aal"])
      amr = claims["amr"] || []

      # Determine next level based on user's factors
      has_verified_factors =
        Enum.any?(session.user.factors, fn factor -> factor.status == :verified end)

      next_level =
        cond do
          has_verified_factors and current_level == :aal1 -> :aal2
          has_verified_factors -> :aal2
          true -> :aal1
        end

      {:ok,
       %{
         current_level: current_level,
         next_level: next_level,
         current_authentication_methods: amr
       }}
    end
  end

  # Private helper functions

  @spec parse_factor(map()) :: {:ok, MFABehaviour.factor()} | {:error, term()}
  defp parse_factor(%{"id" => id, "type" => type} = data) do
    factor_type = parse_factor_type(type)
    status = parse_factor_status(data["status"])

    base_factor = %{
      id: id,
      friendly_name: data["friendly_name"],
      factor_type: factor_type,
      status: status,
      created_at: data["created_at"],
      updated_at: data["updated_at"],
      last_challenged_at: data["last_challenged_at"]
    }

    case factor_type do
      :totp ->
        {:ok,
         Map.put(base_factor, :totp, %{
           qr_code: data["totp"]["qr_code"],
           secret: data["totp"]["secret"],
           uri: data["totp"]["uri"]
         })}

      :phone ->
        {:ok, Map.put(base_factor, :phone, data["phone"])}

      :webauthn ->
        {:ok, base_factor}

      _ ->
        {:error, :unknown_factor_type}
    end
  end

  defp parse_factor_from_user(%User.Factor{} = factor) do
    base = %{
      id: factor.id,
      friendly_name: factor.friendly_name,
      factor_type: factor.factor_type,
      status: factor.status,
      created_at: factor.created_at,
      updated_at: factor.updated_at,
      last_challenged_at: nil
    }

    {:ok, base}
  end

  @spec parse_challenge_response(map()) ::
          {:ok, MFABehaviour.challenge_response() | MFABehaviour.webauthn_challenge_response()}
          | {:error, term()}
  defp parse_challenge_response(%{"id" => id, "type" => type, "expires_at" => expires_at} = data) do
    factor_type = parse_factor_type(type)

    base_response = %{
      id: id,
      type: factor_type,
      expires_at: expires_at
    }

    case {factor_type, data["webauthn"]} do
      {:webauthn, webauthn} when not is_nil(webauthn) ->
        {:ok, Map.put(base_response, :webauthn, webauthn)}

      _ ->
        {:ok, base_response}
    end
  end

  defp parse_factor_type("totp"), do: :totp
  defp parse_factor_type("phone"), do: :phone
  defp parse_factor_type("webauthn"), do: :webauthn
  defp parse_factor_type(_), do: :unknown

  defp parse_factor_status("verified"), do: :verified
  defp parse_factor_status("unverified"), do: :unverified
  defp parse_factor_status(_), do: :unknown

  defp parse_aal_level("aal1"), do: :aal1
  defp parse_aal_level("aal2"), do: :aal2
  defp parse_aal_level(_), do: nil

  defp decode_jwt_claims(token) do
    # JWT structure: header.payload.signature
    # We only need the payload (middle part)
    with [_header, payload, _sig] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false) do
      Supabase.decode_json(json)
    else
      :error -> {:error, :invalid_jwt}
      _ -> {:error, :invalid_jwt_format}
    end
  end
end
