defmodule Supabase.Auth.MFAFixture do
  @moduledoc """
  This module is used to generate fixtures for MFA-related data.
  """

  @doc "Generate a TOTP factor fixture."
  def totp_factor_fixture(attrs \\ %{}) do
    default = %{
      "id" => "11111111-1111-1111-1111-111111111111",
      "type" => "totp",
      "friendly_name" => "My Authenticator",
      "status" => "unverified",
      "totp" => %{
        "qr_code" => "data:image/svg+xml;utf-8,<svg xmlns='http://www.w3.org/2000/svg' width='200' height='200'/>",
        "secret" => "JBSWY3DPEHPK3PXP",
        "uri" => "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
      },
      "created_at" => "2024-01-01T00:00:00.000000Z",
      "updated_at" => "2024-01-01T00:00:00.000000Z",
      "last_challenged_at" => nil
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a TOTP factor fixture as JSON."
  def totp_factor_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> totp_factor_fixture() |> json.encode!()
  end

  @doc "Generate a verified TOTP factor fixture."
  def verified_totp_factor_fixture(attrs \\ %{}) do
    totp_factor_fixture(Map.put(attrs, "status", "verified"))
  end

  @doc "Generate a Phone factor fixture."
  def phone_factor_fixture(attrs \\ %{}) do
    default = %{
      "id" => "22222222-2222-2222-2222-222222222222",
      "type" => "phone",
      "friendly_name" => "My Phone",
      "status" => "unverified",
      "phone" => "+1234567890",
      "created_at" => "2024-01-01T00:00:00.000000Z",
      "updated_at" => "2024-01-01T00:00:00.000000Z",
      "last_challenged_at" => nil
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a Phone factor fixture as JSON."
  def phone_factor_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> phone_factor_fixture() |> json.encode!()
  end

  @doc "Generate a verified Phone factor fixture."
  def verified_phone_factor_fixture(attrs \\ %{}) do
    phone_factor_fixture(Map.put(attrs, "status", "verified"))
  end

  @doc "Generate a WebAuthn factor fixture."
  def webauthn_factor_fixture(attrs \\ %{}) do
    default = %{
      "id" => "33333333-3333-3333-3333-333333333333",
      "type" => "webauthn",
      "friendly_name" => "YubiKey",
      "status" => "unverified",
      "created_at" => "2024-01-01T00:00:00.000000Z",
      "updated_at" => "2024-01-01T00:00:00.000000Z",
      "last_challenged_at" => nil
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a WebAuthn factor fixture as JSON."
  def webauthn_factor_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> webauthn_factor_fixture() |> json.encode!()
  end

  @doc "Generate a verified WebAuthn factor fixture."
  def verified_webauthn_factor_fixture(attrs \\ %{}) do
    webauthn_factor_fixture(Map.put(attrs, "status", "verified"))
  end

  @doc "Generate a TOTP challenge response fixture."
  def totp_challenge_fixture(attrs \\ %{}) do
    default = %{
      "id" => "challenge-id-123",
      "type" => "totp",
      "expires_at" => 1_735_689_600
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a TOTP challenge response fixture as JSON."
  def totp_challenge_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> totp_challenge_fixture() |> json.encode!()
  end

  @doc "Generate a Phone challenge response fixture."
  def phone_challenge_fixture(attrs \\ %{}) do
    default = %{
      "id" => "challenge-id-456",
      "type" => "phone",
      "expires_at" => 1_735_689_600
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a Phone challenge response fixture as JSON."
  def phone_challenge_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> phone_challenge_fixture() |> json.encode!()
  end

  @doc "Generate a WebAuthn challenge response fixture."
  def webauthn_challenge_fixture(attrs \\ %{}) do
    default = %{
      "id" => "challenge-id-789",
      "type" => "webauthn",
      "expires_at" => 1_735_689_600,
      "webauthn" => %{
        "type" => "create",
        "credential_options" => %{
          "publicKey" => %{
            "challenge" => "abc123",
            "rp" => %{"name" => "Example", "id" => "example.com"}
          }
        }
      }
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a WebAuthn challenge response fixture as JSON."
  def webauthn_challenge_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> webauthn_challenge_fixture() |> json.encode!()
  end

  @doc "Generate a JWT token with AAL claims."
  def jwt_token_fixture(attrs \\ []) do
    attrs = Map.new(attrs)
    aal = Map.get(attrs, :aal, "aal1")
    amr = Map.get(attrs, :amr, ["password"])

    claims = %{
      "aal" => aal,
      "amr" => amr,
      "sub" => "11111111-1111-1111-1111-111111111111",
      "exp" => 9_999_999_999
    }

    json = Supabase.json_library()
    payload = json.encode!(claims)
    encoded_payload = Base.url_encode64(payload, padding: false)

    # JWT structure: header.payload.signature
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.#{encoded_payload}.signature"
  end
end
