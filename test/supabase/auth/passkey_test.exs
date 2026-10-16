defmodule Supabase.Auth.PasskeyTest do
  use ExUnit.Case, async: true

  import Mox
  import Supabase.Auth.PasskeyFixture
  import Supabase.Auth.SessionFixture

  alias Supabase.Auth.Passkey
  alias Supabase.Auth.Session
  alias Supabase.Fetcher.Request

  @moduletag capture_log: true

  setup :verify_on_exit!

  @mock TestHTTPClient

  setup_all do
    Application.put_env(:supabase_auth, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_auth, :http_client)
    end)
  end

  setup do
    client = Supabase.init_client!("http://localhost:54321", "test-api-key")
    session = session_fixture(access_token: "test-token-123")

    {:ok, client: client, session: session, json: Supabase.json_library()}
  end

  describe "start_registration/2" do
    test "successfully gets registration options", %{client: client, session: session, json: json} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/passkeys/registration/options"
        assert {"authorization", "Bearer test-token-123"} in req.headers
        assert json.decode!(req.body) == %{}

        response_body = registration_options_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %{challenge_id: challenge_id, options: options, expires_at: expires_at}} =
               Passkey.start_registration(client, session)

      assert is_binary(challenge_id)
      assert is_map(options)
      assert options["challenge"] == "TEST-CHALLENGE-BASE64URL"
      assert is_integer(expires_at)
    end

    test "returns error when the server rejects registration", %{
      client: client,
      session: session
    } do
      expect(@mock, :request, fn %Request{}, _opts ->
        body = ~s|{"code": "too_many_passkeys", "msg": "too many passkeys"}|
        {:ok, %Finch.Response{status: 422, body: body, headers: []}}
      end)

      assert {:error, %Supabase.Error{} = err} = Passkey.start_registration(client, session)
      assert err.metadata.resp_body["code"] == "too_many_passkeys"
    end
  end

  describe "verify_registration/4" do
    test "successfully verifies a registration with a verbatim credential", %{
      client: client,
      session: session,
      json: json
    } do
      credential = attestation_credential_fixture()

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/passkeys/registration/verify"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        body = json.decode!(req.body)
        assert body["challenge_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        assert body["credential"] == credential

        response_body = passkey_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, passkey} =
               Passkey.verify_registration(
                 client,
                 session,
                 "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                 credential
               )

      assert passkey.id == "99999999-8888-7777-6666-555555555555"
      assert passkey.friendly_name == "My YubiKey"
      assert passkey.created_at == "2026-01-01T00:00:00.000000Z"
    end

    test "returns an error when the challenge is empty (schema rejects before http)", %{
      client: client,
      session: session
    } do
      assert {:error, %Ecto.Changeset{}} =
               Passkey.verify_registration(client, session, "", attestation_credential_fixture())
    end

    test "rejects a non-map credential before any http call", %{client: client, session: session} do
      assert_raise FunctionClauseError, fn ->
        Passkey.verify_registration(
          client,
          session,
          "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
          nil
        )
      end
    end

    test "returns error when the challenge is rejected", %{client: client, session: session} do
      credential = attestation_credential_fixture()

      expect(@mock, :request, fn %Request{}, _opts ->
        body = ~s|{"code": "webauthn_challenge_not_found", "msg": "challenge not found"}|
        {:ok, %Finch.Response{status: 400, body: body, headers: []}}
      end)

      assert {:error, %Supabase.Error{} = err} =
               Passkey.verify_registration(
                 client,
                 session,
                 "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                 credential
               )

      assert err.metadata.resp_body["code"] == "webauthn_challenge_not_found"
    end
  end

  describe "start_authentication/2" do
    test "successfully gets authentication options without captcha", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/passkeys/authentication/options"
        assert Request.get_header(req, "authorization") == "Bearer test-api-key"
        assert Supabase.json_library().decode!(req.body) == %{"gotrue_meta_security" => %{}}

        response_body = authentication_options_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %{challenge_id: challenge_id, options: options}} =
               Passkey.start_authentication(client)

      assert is_binary(challenge_id)
      assert is_map(options)
    end

    test "forwards the captcha token", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert Request.get_header(req, "authorization") == "Bearer test-api-key"

        assert Supabase.json_library().decode!(req.body) ==
                 %{"gotrue_meta_security" => %{"captcha_token" => "captcha-token"}}

        response_body = authentication_options_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %{challenge_id: _}} =
               Passkey.start_authentication(client, %{captcha_token: "captcha-token"})
    end
  end

  describe "verify_authentication/3" do
    test "successfully verifies sign-in and parses the session", %{client: client, json: json} do
      credential = assertion_credential_fixture()

      user_map = %{
        "id" => "11111111-1111-1111-1111-111111111111",
        "email" => "example@email.com",
        "aud" => "authenticated",
        "role" => "authenticated",
        "app_metadata" => %{"provider" => "email", "providers" => ["email"]},
        "user_metadata" => %{},
        "created_at" => "2024-01-01T00:00:00.000000Z",
        "factors" => [],
        "identities" => [
          %{
            "id" => "104505643897342987643",
            "identity_id" => "22222222-2222-2222-2222-222222222222",
            "user_id" => "11111111-1111-1111-1111-111111111111",
            "provider" => "google",
            "email" => "user@gmail.com",
            "identity_data" => %{"email" => "user@gmail.com", "sub" => "104505643897342987643"},
            "last_sign_in_at" => "2024-01-01T00:00:00.000000Z",
            "created_at" => "2024-01-01T00:00:00.000000Z",
            "updated_at" => "2024-01-01T00:00:00.000000Z"
          }
        ]
      }

      response_body =
        json.encode!(%{
          "access_token" => "new-token",
          "refresh_token" => "refresh-token",
          "expires_in" => 3600,
          "token_type" => "bearer",
          "user" => user_map
        })

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/passkeys/authentication/verify"
        assert Request.get_header(req, "authorization") == "Bearer test-api-key"

        body = json.decode!(req.body)
        assert body["challenge_id"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        assert body["credential"] == credential

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %Session{} = session} =
               Passkey.verify_authentication(
                 client,
                 "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                 credential
               )

      assert session.access_token == "new-token"
      identity = hd(session.user.identities)
      assert identity.id == "104505643897342987643"
      assert identity.identity_id == "22222222-2222-2222-2222-222222222222"
      assert identity.email == "user@gmail.com"
    end

    test "returns error when verification fails", %{client: client} do
      credential = assertion_credential_fixture()

      expect(@mock, :request, fn %Request{}, _opts ->
        body = ~s|{"code": "webauthn_verification_failed", "msg": "verification failed"}|
        {:ok, %Finch.Response{status: 400, body: body, headers: []}}
      end)

      assert {:error, %Supabase.Error{} = err} =
               Passkey.verify_authentication(
                 client,
                 "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                 credential
               )

      assert err.metadata.resp_body["code"] == "webauthn_verification_failed"
    end
  end

  describe "list/2" do
    test "successfully lists passkeys", %{client: client, session: session, json: json} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/passkeys"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        response_body = json.encode!([passkey_fixture()])

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, [passkey]} = Passkey.list(client, session)
      assert passkey.id == "99999999-8888-7777-6666-555555555555"
      assert passkey.friendly_name == "My YubiKey"
    end

    test "returns error on server failure", %{client: client, session: session} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 500, body: ~s|{"msg": "internal error"}|, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Passkey.list(client, session)
    end
  end

  describe "update/4" do
    test "successfully renames a passkey", %{client: client, session: session, json: json} do
      passkey_id = "99999999-8888-7777-6666-555555555555"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :patch
        assert req.url.path =~ "/passkeys/#{passkey_id}"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        body = json.decode!(req.body)
        assert body == %{"friendly_name" => "Renamed key"}

        response_body = passkey_fixture_json(%{"friendly_name" => "Renamed key"})

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, passkey} = Passkey.update(client, session, passkey_id, "Renamed key")
      assert passkey.friendly_name == "Renamed key"
    end

    test "returns an error when friendly_name is empty (schema rejects before http)", %{
      client: client,
      session: session
    } do
      assert {:error, %Ecto.Changeset{}} =
               Passkey.update(client, session, "99999999-8888-7777-6666-555555555555", "")
    end

    test "returns an error when friendly_name is too long", %{client: client, session: session} do
      assert {:error, %Ecto.Changeset{}} =
               Passkey.update(client, session, "99999999-8888-7777-6666-555555555555", String.duplicate("a", 121))
    end
  end

  describe "delete/3" do
    test "successfully deletes a passkey", %{client: client, session: session} do
      passkey_id = "99999999-8888-7777-6666-555555555555"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/passkeys/#{passkey_id}"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        {:ok, %Finch.Response{status: 204, body: ~s|{}|, headers: []}}
      end)

      assert :ok = Passkey.delete(client, session, passkey_id)
    end

    test "returns an error when the passkey doesn't exist", %{client: client, session: session} do
      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 404, body: ~s|{"code": "passkey_not_found", "msg": "not found"}|, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} =
               Passkey.delete(client, session, "99999999-8888-7777-6666-555555555555")
    end
  end
end
