defmodule Supabase.Auth.PasskeyFixture do
  @moduledoc """
  This module is used to generate fixtures for passkey-related data.
  """

  @doc "Generate a passkey item fixture."
  def passkey_fixture(attrs \\ %{}) do
    default = %{
      "id" => "99999999-8888-7777-6666-555555555555",
      "friendly_name" => "My YubiKey",
      "created_at" => "2026-01-01T00:00:00.000000Z",
      "last_used_at" => nil
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate a passkey item fixture as JSON."
  def passkey_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> passkey_fixture() |> json.encode!()
  end

  @doc "Generate WebAuthn registration (creation) options fixture."
  def registration_options_fixture(attrs \\ %{}) do
    default = %{
      "challenge_id" => "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "options" => %{
        "rp" => %{"id" => "localhost", "name" => "Test RP"},
        "user" => %{
          "id" => "dXNlci1pZA",
          "name" => "passkey-user@example.com",
          "displayName" => "Passkey User"
        },
        "challenge" => "TEST-CHALLENGE-BASE64URL",
        "pubKeyCredParams" => [%{"type" => "public-key", "alg" => -7}],
        "timeout" => 60_000,
        "attestation" => "none"
      },
      "expires_at" => System.os_time(:second) + 300
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate WebAuthn registration (creation) options fixture as JSON."
  def registration_options_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> registration_options_fixture() |> json.encode!()
  end

  @doc "Generate WebAuthn authentication (request) options fixture."
  def authentication_options_fixture(attrs \\ %{}) do
    default = %{
      "challenge_id" => "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "options" => %{
        "challenge" => "TEST-CHALLENGE-BASE64URL",
        "rpId" => "localhost",
        "timeout" => 60_000,
        "userVerification" => "preferred"
      },
      "expires_at" => System.os_time(:second) + 300
    }

    Map.merge(default, Map.new(attrs))
  end

  @doc "Generate WebAuthn authentication (request) options fixture as JSON."
  def authentication_options_fixture_json(attrs \\ %{}) do
    json = Supabase.json_library()
    attrs |> authentication_options_fixture() |> json.encode!()
  end

  @doc "Generate a passthrough WebAuthn registration credential fixture."
  def attestation_credential_fixture do
    %{
      "id" => "cred-attestation-id-base64url",
      "rawId" => "cred-attestation-raw-id-base64url",
      "type" => "public-key",
      "clientExtensionResults" => %{},
      "response" => %{
        "attestationObject" => "YXR0ZXN0YXRpb24tb2JqZWN0LWJhc2U2NC11cmw",
        "clientDataJSON" => "Y2xpZW50LWRhdGEtanNvbi1iYXNlNjQtdXJs"
      }
    }
  end

  @doc "Generate a passthrough WebAuthn authentication credential fixture."
  def assertion_credential_fixture do
    %{
      "id" => "cred-assertion-id-base64url",
      "rawId" => "cred-assertion-raw-id-base64url",
      "type" => "public-key",
      "clientExtensionResults" => %{},
      "response" => %{
        "authenticatorData" => "YXV0aGVudGljYXRvci1kYXRhLWJhc2U2NC11cmw",
        "clientDataJSON" => "Y2xpZW50LWRhdGEtanNvbi1iYXNlNjQtdXJs",
        "signature" => "c2lnbmF0dXJlLWJhc2U2NC11cmw"
      }
    }
  end
end
