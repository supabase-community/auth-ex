defmodule Supabase.Auth.MFATest do
  use ExUnit.Case, async: true

  import Mox
  import Supabase.Auth.MFAFixture
  import Supabase.Auth.SessionFixture
  import Supabase.Auth.UserFixture

  alias Supabase.Auth.MFA
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
    client = Supabase.init_client!("https://localhost:54321", "test-api-key")
    session = session_fixture(access_token: "test-token-123")

    {:ok, client: client, session: session, json: Supabase.json_library()}
  end

  describe "enroll/3 with TOTP" do
    test "successfully enrolls a TOTP factor", %{client: client, session: session, json: json} do
      params = %{
        factor_type: :totp,
        friendly_name: "My Authenticator",
        issuer: "Example"
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        body = json.decode!(req.body)
        assert body["factor_type"] == "totp"
        assert body["friendly_name"] == "My Authenticator"
        assert body["issuer"] == "Example"

        response_body = totp_factor_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, factor} = MFA.enroll(client, session, params)
      assert factor.factor_type == :totp
      assert factor.friendly_name == "My Authenticator"
      assert factor.status == :unverified
      assert factor.totp.qr_code =~ "data:image/svg+xml"
      assert factor.totp.secret == "JBSWY3DPEHPK3PXP"
      assert factor.totp.uri =~ "otpauth://totp/"
    end

    test "successfully enrolls a TOTP factor without optional fields", %{
      client: client,
      session: session
    } do
      params = %{factor_type: :totp}

      expect(@mock, :request, fn %Request{}, _opts ->
        response_body = totp_factor_fixture_json(%{"friendly_name" => nil})

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, factor} = MFA.enroll(client, session, params)
      assert factor.factor_type == :totp
      assert is_nil(factor.friendly_name)
    end

    test "returns error when enrollment fails", %{client: client, session: session} do
      params = %{factor_type: :totp}

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 400, body: ~s|{"error": "bad request"}|, headers: []}}
      end)

      assert {:error, _} = MFA.enroll(client, session, params)
    end
  end

  describe "enroll/3 with Phone" do
    test "successfully enrolls a Phone factor", %{client: client, session: session, json: json} do
      params = %{
        factor_type: :phone,
        phone: "+1234567890",
        friendly_name: "My Phone"
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors"

        body = json.decode!(req.body)
        assert body["factor_type"] == "phone"
        assert body["phone"] == "+1234567890"
        assert body["friendly_name"] == "My Phone"

        response_body = phone_factor_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, factor} = MFA.enroll(client, session, params)
      assert factor.factor_type == :phone
      assert factor.phone == "+1234567890"
      assert factor.status == :unverified
    end

    test "returns error when phone is missing", %{client: client, session: session} do
      params = %{factor_type: :phone}

      assert {:error, %Ecto.Changeset{}} = MFA.enroll(client, session, params)
    end
  end

  describe "enroll/3 with WebAuthn" do
    test "successfully enrolls a WebAuthn factor", %{
      client: client,
      session: session,
      json: json
    } do
      params = %{
        factor_type: :webauthn,
        friendly_name: "YubiKey"
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors"

        body = json.decode!(req.body)
        assert body["factor_type"] == "webauthn"
        assert body["friendly_name"] == "YubiKey"

        response_body = webauthn_factor_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, factor} = MFA.enroll(client, session, params)
      assert factor.factor_type == :webauthn
      assert factor.friendly_name == "YubiKey"
    end
  end

  describe "challenge/4 with TOTP" do
    test "successfully creates a TOTP challenge", %{client: client, session: session} do
      factor_id = "factor-123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors/#{factor_id}/challenge"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        response_body = totp_challenge_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, challenge} = MFA.challenge(client, session, factor_id, %{})
      assert challenge.id == "challenge-id-123"
      assert challenge.type == :totp
      assert is_integer(challenge.expires_at)
    end
  end

  describe "challenge/4 with Phone" do
    test "successfully creates a Phone challenge via SMS", %{
      client: client,
      session: session,
      json: json
    } do
      factor_id = "factor-456"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors/#{factor_id}/challenge"

        body = json.decode!(req.body)
        assert body["channel"] == "sms"

        response_body = phone_challenge_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, challenge} = MFA.challenge(client, session, factor_id, %{channel: :sms})
      assert challenge.id == "challenge-id-456"
      assert challenge.type == :phone
    end

    test "successfully creates a Phone challenge via WhatsApp", %{
      client: client,
      session: session,
      json: json
    } do
      factor_id = "factor-456"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        body = json.decode!(req.body)
        assert body["channel"] == "whatsapp"

        response_body = phone_challenge_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, challenge} =
               MFA.challenge(client, session, factor_id, %{channel: :whatsapp})

      assert challenge.type == :phone
    end

    test "returns error for invalid channel", %{client: client, session: session} do
      factor_id = "factor-456"

      assert {:error, %Ecto.Changeset{}} =
               MFA.challenge(client, session, factor_id, %{channel: :invalid})
    end
  end

  describe "challenge/4 with WebAuthn" do
    test "successfully creates a WebAuthn challenge", %{
      client: client,
      session: session,
      json: json
    } do
      factor_id = "factor-789"

      webauthn_params = %{
        webauthn: %{
          rp_id: "example.com",
          rp_origins: ["https://example.com"]
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors/#{factor_id}/challenge"

        body = json.decode!(req.body)
        assert body["webauthn"]["rp_id"] == "example.com"
        assert body["webauthn"]["rp_origins"] == ["https://example.com"]

        response_body = webauthn_challenge_fixture_json()

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, challenge} = MFA.challenge(client, session, factor_id, webauthn_params)
      assert challenge.id == "challenge-id-789"
      assert challenge.type == :webauthn
      assert challenge.webauthn["type"] == "create"
      assert is_map(challenge.webauthn["credential_options"])
    end
  end

  describe "verify/5 with code (TOTP/Phone)" do
    test "successfully verifies a TOTP code", %{client: client, session: session, json: json} do
      factor_id = "factor-123"
      challenge_id = "challenge-456"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/factors/#{factor_id}/verify"

        body = json.decode!(req.body)
        assert body["challenge_id"] == challenge_id
        assert body["code"] == "123456"

        user = Map.from_struct(user_fixture())
        response_body = session_fixture_json(access_token: "new-token-789", user: user)

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %Session{} = new_session} =
               MFA.verify(client, session, factor_id, challenge_id, %{code: "123456"})

      assert new_session.access_token == "new-token-789"
    end

    test "returns error for invalid code length", %{client: client, session: session} do
      factor_id = "factor-123"
      challenge_id = "challenge-456"

      assert {:error, %Ecto.Changeset{}} =
               MFA.verify(client, session, factor_id, challenge_id, %{code: "123"})
    end

    test "returns error when verification fails", %{client: client, session: session} do
      factor_id = "factor-123"
      challenge_id = "challenge-456"

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 400, body: ~s|{"error": "invalid code"}|, headers: []}}
      end)

      assert {:error, _} =
               MFA.verify(client, session, factor_id, challenge_id, %{code: "000000"})
    end
  end

  describe "verify/5 with WebAuthn" do
    test "successfully verifies a WebAuthn credential", %{
      client: client,
      session: session,
      json: json
    } do
      factor_id = "factor-789"
      challenge_id = "challenge-abc"

      webauthn_params = %{
        webauthn: %{
          type: "create",
          rp_id: "example.com",
          credential_response: %{"id" => "credential-123"}
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post

        body = json.decode!(req.body)
        assert body["challenge_id"] == challenge_id
        assert body["webauthn"]["type"] == "create"

        user = Map.from_struct(user_fixture())
        response_body = session_fixture_json(access_token: "new-token-webauthn", user: user)

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %Session{} = new_session} =
               MFA.verify(client, session, factor_id, challenge_id, webauthn_params)

      assert new_session.access_token == "new-token-webauthn"
    end
  end

  describe "unenroll/3" do
    test "successfully unenrolls a factor", %{client: client, session: session, json: json} do
      factor_id = "factor-to-delete"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/factors/#{factor_id}"
        assert {"authorization", "Bearer test-token-123"} in req.headers

        response_body = json.encode!(%{"id" => factor_id})

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %{id: ^factor_id}} = MFA.unenroll(client, session, factor_id)
    end

    test "returns error when factor doesn't exist", %{client: client, session: session} do
      factor_id = "non-existent"

      expect(@mock, :request, fn %Request{}, _opts ->
        {:ok, %Finch.Response{status: 404, body: ~s|{"error": "not found"}|, headers: []}}
      end)

      assert {:error, _} = MFA.unenroll(client, session, factor_id)
    end
  end

  describe "challenge_and_verify/4" do
    test "successfully challenges and verifies in one call", %{
      client: client,
      session: session,
      json: json
    } do
      factor_id = "totp-factor-123"
      code = "654321"

      # First call: challenge
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.url.path =~ "/factors/#{factor_id}/challenge"

        response_body = totp_challenge_fixture_json(%{"id" => "challenge-xyz"})

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      # Second call: verify
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.url.path =~ "/factors/#{factor_id}/verify"

        body = json.decode!(req.body)
        assert body["challenge_id"] == "challenge-xyz"
        assert body["code"] == code

        user = Map.from_struct(user_fixture())
        response_body = session_fixture_json(access_token: "final-token", user: user)

        {:ok, %Finch.Response{status: 200, body: response_body, headers: []}}
      end)

      assert {:ok, %Session{} = new_session} =
               MFA.challenge_and_verify(client, session, factor_id, code)

      assert new_session.access_token == "final-token"
    end

    test "returns error for invalid code", %{client: client, session: session} do
      factor_id = "totp-factor-123"

      assert {:error, %Ecto.Changeset{}} =
               MFA.challenge_and_verify(client, session, factor_id, "12")
    end
  end

  describe "list_factors/2" do
    test "successfully lists all factors categorized by type", %{client: client} do
      factors = [
        verified_totp_factor_fixture(),
        phone_factor_fixture(),
        verified_webauthn_factor_fixture()
      ]

      factor_structs = Enum.map(factors, &build_factor_struct/1)
      session = session_fixture(user: %{factors: factor_structs})

      assert {:ok, result} = MFA.list_factors(client, session)

      assert length(result.all) == 3
      assert length(result.totp) == 1
      assert Enum.empty?(result.phone)
      assert length(result.webauthn) == 1

      [totp_factor] = result.totp
      assert totp_factor.factor_type == :totp
      assert totp_factor.status == :verified
    end

    test "returns empty lists when no factors exist", %{client: client} do
      session = session_fixture(user: %{factors: []})

      assert {:ok, result} = MFA.list_factors(client, session)

      assert result.all == []
      assert result.totp == []
      assert result.phone == []
      assert result.webauthn == []
    end

    test "only includes verified factors in type-specific lists", %{client: client} do
      factors = [
        verified_totp_factor_fixture(%{"id" => "totp-1"}),
        totp_factor_fixture(%{"id" => "totp-2", "status" => "unverified"}),
        verified_phone_factor_fixture(%{"id" => "phone-1"})
      ]

      factor_structs = Enum.map(factors, &build_factor_struct/1)
      session = session_fixture(user: %{factors: factor_structs})

      assert {:ok, result} = MFA.list_factors(client, session)

      # All factors in 'all' list
      assert length(result.all) == 3

      # Only verified in type-specific lists
      assert length(result.totp) == 1
      assert length(result.phone) == 1
    end
  end

  describe "get_authenticator_assurance_level/2" do
    test "returns AAL1 for user without MFA", %{client: client} do
      jwt_token = jwt_token_fixture(aal: "aal1", amr: ["password"])
      session = session_fixture(access_token: jwt_token, user: %{factors: []})

      assert {:ok, result} = MFA.get_authenticator_assurance_level(client, session)

      assert result.current_level == :aal1
      assert result.next_level == :aal1
      assert result.current_authentication_methods == ["password"]
    end

    test "returns AAL2 for user with verified MFA", %{client: client} do
      jwt_token = jwt_token_fixture(aal: "aal2", amr: ["password", "totp"])

      verified_factor = build_factor_struct(verified_totp_factor_fixture())

      session = session_fixture(access_token: jwt_token, user: %{factors: [verified_factor]})

      assert {:ok, result} = MFA.get_authenticator_assurance_level(client, session)

      assert result.current_level == :aal2
      assert result.next_level == :aal2
      assert result.current_authentication_methods == ["password", "totp"]
    end

    test "returns AAL1 with next level AAL2 when user has unverified factors", %{
      client: client
    } do
      jwt_token = jwt_token_fixture(aal: "aal1", amr: ["password"])

      verified_factor = build_factor_struct(verified_totp_factor_fixture())

      session = session_fixture(access_token: jwt_token, user: %{factors: [verified_factor]})

      assert {:ok, result} = MFA.get_authenticator_assurance_level(client, session)

      assert result.current_level == :aal1
      assert result.next_level == :aal2
    end

    test "returns error for invalid JWT", %{client: client} do
      session = session_fixture(access_token: "invalid-jwt-token", user: %{factors: []})

      assert {:error, :invalid_jwt_format} =
               MFA.get_authenticator_assurance_level(client, session)
    end
  end

  # Helper function to build Factor structs from fixture maps
  defp build_factor_struct(factor_map) do
    alias Supabase.Auth.User.Factor

    %Factor{
      id: factor_map["id"],
      friendly_name: factor_map["friendly_name"],
      factor_type: parse_factor_type(factor_map["type"]),
      status: parse_factor_status(factor_map["status"]),
      created_at: factor_map["created_at"],
      updated_at: factor_map["updated_at"]
    }
  end

  defp parse_factor_type("totp"), do: :totp
  defp parse_factor_type("phone"), do: :phone
  defp parse_factor_type("webauthn"), do: :webauthn

  defp parse_factor_status("verified"), do: :verified
  defp parse_factor_status("unverified"), do: :unverified
end
