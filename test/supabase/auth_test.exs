defmodule Supabase.AuthTest do
  use ExUnit.Case, async: true

  import Mox
  import Supabase.Auth.ErrorFixture
  import Supabase.Auth.ServerHealthFixture
  import Supabase.Auth.ServerSettingsFixture
  import Supabase.Auth.SessionFixture
  import Supabase.Auth.UserFixture

  alias Supabase.Auth
  alias Supabase.Auth.Schemas.ServerHealth
  alias Supabase.Auth.Schemas.ServerSettings
  alias Supabase.Auth.Session
  alias Supabase.Auth.User
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

    {:ok, client: client, json: Supabase.json_library()}
  end

  describe "get_user/2" do
    test "successfully retrieves an existing user", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert {:ok, %User{} = user} = Auth.get_user(client, session)
      assert user.id == "123"
    end

    test "returns an error when user doesn't exists", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        {:ok, %Finch.Response{status: 404, body: "{}", headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert {:error, %Supabase.Error{}} = Auth.get_user(client, session)
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      session = %Session{access_token: "123"}
      assert {:error, %Supabase.Error{}} = Auth.get_user(client, session)
    end
  end

  describe "sign_in_with_id_token/2" do
    test "successfully sings in an user with ID token", %{client: client, json: json} do
      data = %{provider: :apple, token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = json.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_in_with_id_token(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on authentication error", %{client: client, json: json} do
      data = %{provider: :apple, token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = json.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.sign_in_with_id_token(client, data)
    end

    test "returns an error on unexpected error", %{client: client, json: json} do
      data = %{provider: :apple, token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = json.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.sign_in_with_id_token(client, data)
    end
  end

  describe "sign_in_with_oauth/2" do
    test "successfully sings in an user with Oauth", %{client: client} do
      data = %{
        provider: :github,
        options: %{
          redirect_to: "http://localhost:3000",
          query_params: %{
            state: "123"
          },
          scopes: ["user:email", "read:user"]
        }
      }

      assert {:ok, %{provider: :github, flow_type: :implicit, url: url_as_string}} =
               Auth.sign_in_with_oauth(client, data)

      url = URI.parse(url_as_string)

      assert url.path =~ "/authorize"
      assert url.query =~ "state=123"
      assert url.query =~ "scopes=user%3Aemail+read%3Auser"
    end
  end

  describe "sign_in_with_otp/2" do
    test "successfully triggers an user signin with email OTP", %{client: client, json: json} do
      data = %{
        email: "john@example.com",
        options: %{
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "create_user" => true,
                 "email" => "john@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => "123"}
               } = json.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      # user should receive an OTP code via email
      assert :ok = Auth.sign_in_with_otp(client, data)
    end

    test "successfully triggers an user signin with phone OTP", %{client: client, json: json} do
      data = %{
        phone: "+5522123456789",
        options: %{
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "channel" => "sms",
                 "create_user" => true,
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "phone" => "+5522123456789"
               } = json.decode!(req.body)

        body = """
        {
          "data": {
            "message_id": "123"
          }
        }
        """

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      # user should receive an OTP code via phone
      assert {:ok, message_id} = Auth.sign_in_with_otp(client, data)
      assert message_id == "123"
    end

    test "successfully triggers an user signin with whatsapp OTP", %{client: client, json: json} do
      data = %{
        phone: "+5522123456789",
        options: %{
          channel: "whatsapp",
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "channel" => "whatsapp",
                 "create_user" => true,
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "phone" => "+5522123456789"
               } = json.decode!(req.body)

        body = """
        {
          "data": {
            "message_id": "123"
          }
        }
        """

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      # user should receive an OTP code via phone
      assert {:ok, message_id} = Auth.sign_in_with_otp(client, data)
      assert message_id == "123"
    end
  end

  describe "verify_otp/2" do
    test "successfully verifies an email OTP code", %{client: client, json: json} do
      for type <- ~w[signup invite magiclink recovery email_change email]a do
        data = %{
          email: "john@example.com",
          token: "123",
          type: type,
          options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
        }

        expect(@mock, :request, fn %Request{} = req, _opts ->
          assert req.method == :post
          assert req.url.path =~ "/verify"
          assert Request.get_query_param(req, "redirect_to") == "http://localhost:3000"

          assert %{
                   "email" => "john@example.com",
                   "go_true_security" => %{"captcha_token" => "123"},
                   "options" => %{
                     "captcha_token" => "123",
                     "redirect_to" => "http://localhost:3000"
                   },
                   "token" => "123",
                   "type" => t
                 } = json.decode!(req.body)

          assert t == Atom.to_string(type)

          user = [id: "123"] |> user_fixture() |> Map.from_struct()
          body = session_fixture_json(access_token: "123", user: user)

          {:ok, %Finch.Response{status: 201, body: body, headers: []}}
        end)

        assert {:ok, %Session{} = session} = Auth.verify_otp(client, data)
        assert session.access_token == "123"
        assert session.user.id == "123"
      end
    end

    test "successfully verifies phone OTP code", %{client: client, json: json} do
      for type <- ~w[sms phone_change]a do
        data = %{
          phone: "+5522123456789",
          token: "123",
          type: type,
          options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
        }

        expect(@mock, :request, fn %Request{} = req, _opts ->
          assert req.method == :post
          assert req.url.path =~ "/verify"
          assert Request.get_query_param(req, "redirect_to") == "http://localhost:3000"

          assert %{
                   "go_true_security" => %{"captcha_token" => "123"},
                   "options" => %{
                     "captcha_token" => "123",
                     "redirect_to" => "http://localhost:3000"
                   },
                   "phone" => "+5522123456789",
                   "token" => "123",
                   "type" => t
                 } = json.decode!(req.body)

          assert t == Atom.to_string(type)

          user = [id: "123"] |> user_fixture() |> Map.from_struct()
          body = session_fixture_json(access_token: "123", user: user)

          {:ok, %Finch.Response{status: 201, body: body, headers: []}}
        end)

        assert {:ok, %Session{} = session} = Auth.verify_otp(client, data)
        assert session.access_token == "123"
        assert session.user.id == "123"
      end
    end

    test "successfully verifies a token hash OTP code", %{client: client, json: json} do
      data = %{
        token_hash: "123",
        type: :signup,
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/verify"
        assert Request.get_query_param(req, "redirect_to") == "http://localhost:3000"

        assert %{
                 "go_true_security" => %{"captcha_token" => "123"},
                 "options" => %{
                   "captcha_token" => "123",
                   "redirect_to" => "http://localhost:3000"
                 },
                 "token_hash" => "123",
                 "type" => "signup"
               } = json.decode!(req.body)

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.verify_otp(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on unauthenticated", %{client: client, json: json} do
      data = %{
        email: "john@example.com",
        token: "123",
        type: :email,
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/verify"
        assert Request.get_query_param(req, "redirect_to") == "http://localhost:3000"

        assert %{
                 "email" => "john@example.com",
                 "go_true_security" => %{"captcha_token" => "123"},
                 "options" => %{
                   "captcha_token" => "123",
                   "redirect_to" => "http://localhost:3000"
                 },
                 "token" => "123",
                 "type" => "email"
               } = json.decode!(req.body)

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.verify_otp(client, data)
    end
  end

  describe "sign_in_with_sso/2" do
    test "successfully signin an user with SSO provider_id", %{client: client, json: json} do
      data = %{
        provider_id: "apple",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/sso"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "provider_id" => "apple"
               } = json.decode!(req.body)

        body = """
        {
          "data": {
            "url": "http://localhost:3000"
          }
        }
        """

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, "http://localhost:3000"} = Auth.sign_in_with_sso(client, data)
    end

    test "successfully signin an user with SSO domain", %{client: client, json: json} do
      data = %{
        domain: "example.org",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/sso"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "domain" => "example.org"
               } = json.decode!(req.body)

        body = """
        {
          "data": {
            "url": "http://localhost:3000/sso"
          }
        }
        """

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, "http://localhost:3000/sso"} = Auth.sign_in_with_sso(client, data)
    end

    test "returns error for SSO signin with invalid parameters", %{client: client} do
      # Missing both domain and provider_id
      data = %{
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      assert {:error, _} = Auth.sign_in_with_sso(client, data)
    end
  end

  describe "sign_in_with_password/2" do
    test "successfully signs in an user with email and password", %{client: client, json: json} do
      data = %{
        email: "john@example.com",
        password: "123",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "email" => "john@example.com",
                 "password" => "123"
               } = json.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "password"

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_in_with_password(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on authentication error", %{client: client, json: json} do
      data = %{
        email: "john@example.com",
        password: "123",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "email" => "john@example.com",
                 "password" => "123"
               } = json.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "password"

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.sign_in_with_password(client, data)
    end
  end

  describe "sign_in_anonymously/2" do
    test "successfully signs in an user anonymously", %{client: client, json: json} do
      data = %{captcha_token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/signup"
        assert %{"gotrue_meta_security" => %{"captcha_token" => "123"}} = json.decode!(req.body)

        user = [id: "123", identities: []] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_in_anonymously(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on unexpected error", %{client: client, json: json} do
      data = %{captcha_token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/signup"

        assert %{
                 "options" => %{"captcha_token" => "123"}
               } = json.decode!(req.body)

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.sign_in_anonymously(client, data)
    end

    test "returns an error on authentication error", %{client: client, json: json} do
      data = %{captcha_token: "123"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/signup"

        assert %{
                 "options" => %{"captcha_token" => "123"}
               } = json.decode!(req.body)

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.sign_in_anonymously(client, data)
    end
  end

  describe "sign_up/2" do
    test "successfully signs up an user with email and password", %{client: client, json: json} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{captcha_token: "123", email_redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/signup"

        assert %{
                 "code_challenge" => nil,
                 "code_challenge_method" => nil,
                 "data" => %{},
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "password" => "123",
                 "phone" => "+5522123456789"
               } = json.decode!(req.body)

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_up(client, data)
      assert session.user.id == "123"
    end

    test "handles provided options.data", %{client: client, json: json} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{
          captcha_token: "123",
          email_redirect_to: "http://localhost:3000",
          data: %{display_name: "Example User", role: "user"}
        }
      }

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert %{
                 "code_challenge" => nil,
                 "code_challenge_method" => nil,
                 "data" => %{
                   "display_name" => "Example User",
                   "role" => "user"
                 },
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "password" => "123",
                 "phone" => "+5522123456789"
               } = json.decode!(req.body)

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_up(client, data)
      assert session.user.id == "123"
    end

    test "returns user_metadata", %{client: client} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{captcha_token: "123", email_redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{}, _opts ->
        user = [user_metadata: %{display_name: "Example User"}] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = Auth.sign_up(client, data)
      assert session.user.user_metadata["display_name"] == "Example User"
    end

    test "handles user only in the sign up payload (when account confirmation email is sent)", %{client: client} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{captcha_token: "123", email_redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{}, _opts ->
        body = user_fixture_json(id: "123")
        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %User{} = user} = Auth.sign_up(client, data)
      assert user.id == "123"
    end

    test "handles error in the sign up", %{client: client} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{captcha_token: "123", email_redirect_to: "http://localhost:3000"}
      }

      expect(@mock, :request, fn %Request{}, _opts ->
        body = error_fixture_json(service: :auth)
        {:error, %Finch.Response{status: 422, body: body, headers: []}}
      end)

      assert {:error, %Supabase.Error{} = error} = Auth.sign_up(client, data)
      assert error.service == :auth
    end
  end

  describe "reset_password_for_email/3" do
    test "successfully sends a recovery password email", %{client: client, json: json} do
      email = "another@example.com"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/recover"

        assert %{
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => nil}
               } = json.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      assert :ok =
               Auth.reset_password_for_email(client, email, redirect_to: "http://localhost:3000")
    end

    test "returns an error on unexpected error", %{client: client} do
      email = "another@example.com"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/recover"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} =
               Auth.reset_password_for_email(client, email, redirect_to: "http://localhost:3000")
    end
  end

  describe "resend/3" do
    test "successfully resends a signup confirm email", %{client: client, json: json} do
      email = "another@example.com"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/resend"

        assert %{
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "type" => "signup"
               } = json.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      assert :ok =
               Auth.resend(client, email, redirect_to: "http://localhost:3000", type: :signup)
    end
  end

  describe "refresh_session/2" do
    test "successfully refreshes the current session", %{client: client, json: json} do
      user = [id: "123"] |> user_fixture() |> Map.from_struct()
      refresh_token = "456"
      session = session_fixture(refresh_token: refresh_token, user: user)

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "refresh_token"
        assert %{"refresh_token" => ^refresh_token} = json.decode!(req.body)

        body = session_fixture_json(access_token: "789", refresh_token: "101112", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = new_session} =
               Auth.refresh_session(client, session.refresh_token)

      assert new_session.access_token == "789"
      assert new_session.refresh_token == "101112"
      assert new_session.user.id == session.user.id
    end

    test "returns an unauthenticated error", %{client: client, json: json} do
      user = [id: "123"] |> user_fixture() |> Map.from_struct()
      refresh_token = "456"
      session = session_fixture(refresh_token: refresh_token, user: user)

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "refresh_token"
        assert %{"refresh_token" => ^refresh_token} = json.decode!(req.body)

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} =
               Auth.refresh_session(client, session.refresh_token)
    end

    test "returns an unexpected error", %{client: client, json: json} do
      user = [id: "123"] |> user_fixture() |> Map.from_struct()
      refresh_token = "456"
      session = session_fixture(refresh_token: refresh_token, user: user)

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "refresh_token"
        assert %{"refresh_token" => ^refresh_token} = json.decode!(req.body)

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} =
               Auth.refresh_session(client, session.refresh_token)
    end
  end

  describe "get_server_settings/1" do
    test "successfully retrieves the server settings", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/settings"

        body = server_settings_fixture_json()

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, %ServerSettings{}} = Auth.get_server_settings(client)
    end

    test "returns an unexpected error", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/settings"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.get_server_settings(client)
    end
  end

  describe "get_server_health/1" do
    test "successfully retrieves the server health", %{client: client} do
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/health"

        body = server_health_fixture_json()

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, %ServerHealth{}} = Auth.get_server_health(client)
    end
  end

  describe "exchange_code_for_session/4" do
    test "successfully exchanges code for session", %{client: client, json: json} do
      auth_code = "auth_code_123"
      code_verifier = "verifier_123"
      redirect_to = "http://localhost:3000/callback"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "pkce"

        assert %{
                 "auth_code" => ^auth_code,
                 "code_verifier" => ^code_verifier,
                 "redirect_to" => ^redirect_to
               } = json.decode!(req.body)

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "456", user: user)

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} =
               Auth.exchange_code_for_session(client, auth_code, code_verifier, %{redirect_to: redirect_to})

      assert session.access_token == "456"
      assert session.user.id == "123"
    end

    test "returns an error on invalid code", %{client: client, json: json} do
      auth_code = "invalid_auth_code"
      code_verifier = "verifier_123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "pkce"

        assert %{
                 "auth_code" => ^auth_code,
                 "code_verifier" => ^code_verifier,
                 "redirect_to" => nil
               } = json.decode!(req.body)

        {:ok,
         %Finch.Response{
           status: 400,
           body: ~s({"error":"invalid_grant","error_description":"Invalid grant"}),
           headers: []
         }}
      end)

      assert {:error, %Supabase.Error{}} =
               Auth.exchange_code_for_session(client, auth_code, code_verifier)
    end

    test "returns an error on unexpected error", %{client: client} do
      auth_code = "auth_code_123"
      code_verifier = "verifier_123"

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "pkce"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} =
               Auth.exchange_code_for_session(client, auth_code, code_verifier)
    end
  end

  describe "reauthenticate/2" do
    test "successfully sends reauthentication request", %{client: client} do
      session = %Session{access_token: "valid_token"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/reauthenticate"
        assert List.keyfind(req.headers, "authorization", 0) == {"authorization", "Bearer valid_token"}

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      assert :ok = Auth.reauthenticate(client, session)
    end

    test "returns an error when unauthorized", %{client: client} do
      session = %Session{access_token: "invalid_token"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/reauthenticate"
        assert List.keyfind(req.headers, "authorization", 0) == {"authorization", "Bearer invalid_token"}

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.reauthenticate(client, session)
    end

    test "returns an error on unexpected error", %{client: client} do
      session = %Session{access_token: "valid_token"}

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/reauthenticate"
        assert List.keyfind(req.headers, "authorization", 0) == {"authorization", "Bearer valid_token"}

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} = Auth.reauthenticate(client, session)
    end
  end

  describe "Session.expired?/1" do
    test "returns false when expires_at is nil" do
      session = %Session{
        access_token: "token",
        refresh_token: "refresh",
        expires_in: 3600,
        expires_at: nil,
        token_type: "bearer"
      }

      refute Session.expired?(session)
    end

    test "returns false when token is not expired (future expiry)" do
      future_time = System.os_time(:second) + 3600

      session = session_fixture(%{expires_at: future_time})

      refute Session.expired?(session)
    end

    test "returns true when token is expired (past expiry)" do
      past_time = System.os_time(:second) - 100

      session = session_fixture(%{expires_at: past_time})

      assert Session.expired?(session)
    end

    test "returns true when token is expired exactly at current time" do
      current_time = System.os_time(:second)

      session = session_fixture(%{expires_at: current_time})

      assert Session.expired?(session)
    end
  end

  describe "Session.expiring_soon?/2" do
    test "returns false when expires_at is nil" do
      session = session_fixture(%{expires_at: nil})

      refute Session.expiring_soon?(session)
    end

    test "returns false when token expires far in the future (beyond default margin)" do
      # Expires in 1 hour (beyond 5 minute default margin)
      future_time = System.os_time(:second) + 3600

      session = session_fixture(%{expires_at: future_time})

      refute Session.expiring_soon?(session)
    end

    test "returns true when token expires within default margin (5 minutes)" do
      # Expires in 4 minutes (within 5 minute margin)
      near_future = System.os_time(:second) + 240

      session = session_fixture(%{expires_at: near_future})

      assert Session.expiring_soon?(session)
    end

    test "returns true when token expires exactly at margin boundary" do
      # Expires exactly at the 5-minute (300 second) boundary
      boundary_time = System.os_time(:second) + 300

      session = session_fixture(%{expires_at: boundary_time})

      assert Session.expiring_soon?(session)
    end

    test "respects custom :within option" do
      # Expires in 2 minutes
      expiry_time = System.os_time(:second) + 120

      session = session_fixture(%{expires_at: expiry_time})

      # With 1 minute margin: not expiring soon
      refute Session.expiring_soon?(session, within: 60)

      # With 3 minute margin: expiring soon
      assert Session.expiring_soon?(session, within: 180)
    end

    test "returns true for already expired token" do
      past_time = System.os_time(:second) - 100

      session = session_fixture(%{expires_at: past_time})

      assert Session.expiring_soon?(session)
    end
  end

  describe "Session.valid?/1" do
    test "returns true for valid session with all required fields and not expired" do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: "valid-refresh",
          expires_at: future_time
        })

      assert Session.valid?(session)
    end

    test "returns false when access_token is nil" do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: nil,
          refresh_token: "valid-refresh",
          expires_at: future_time
        })

      refute Session.valid?(session)
    end

    test "returns false when refresh_token is nil" do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: nil,
          expires_at: future_time
        })

      refute Session.valid?(session)
    end

    test "returns false when both tokens are nil" do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: nil,
          refresh_token: nil,
          expires_at: future_time
        })

      refute Session.valid?(session)
    end

    test "returns false when session is expired even with valid tokens" do
      past_time = System.os_time(:second) - 100

      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: "valid-refresh",
          expires_at: past_time
        })

      refute Session.valid?(session)
    end

    test "returns true when session has no expires_at (nil) but has tokens" do
      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: "valid-refresh",
          expires_at: nil
        })

      assert Session.valid?(session)
    end
  end

  describe "Session.needs_refresh?/2" do
    test "returns false for fresh session (not expiring soon or expired)" do
      future_time = System.os_time(:second) + 3600

      session = session_fixture(%{expires_at: future_time})

      refute Session.needs_refresh?(session)
    end

    test "returns true when session is expiring soon (within default margin)" do
      near_future = System.os_time(:second) + 240

      session = session_fixture(%{expires_at: near_future})

      assert Session.needs_refresh?(session)
    end

    test "returns true when session is already expired" do
      past_time = System.os_time(:second) - 100

      session = session_fixture(%{expires_at: past_time})

      assert Session.needs_refresh?(session)
    end

    test "respects custom :within option" do
      # Expires in 2 minutes
      expiry_time = System.os_time(:second) + 120

      session = session_fixture(%{expires_at: expiry_time})

      # With 1 minute margin: doesn't need refresh
      refute Session.needs_refresh?(session, within: 60)

      # With 3 minute margin: needs refresh
      assert Session.needs_refresh?(session, within: 180)
    end

    test "returns false when expires_at is nil" do
      session = session_fixture(%{expires_at: nil})

      refute Session.needs_refresh?(session)
    end
  end

  describe "Session.seconds_until_expiry/1" do
    test "returns nil when expires_at is nil" do
      session = session_fixture(%{expires_at: nil})

      assert Session.seconds_until_expiry(session) == nil
    end

    test "returns seconds until expiry for future expiry" do
      future_time = System.os_time(:second) + 1000

      session = session_fixture(%{expires_at: future_time})

      seconds = Session.seconds_until_expiry(session)

      # Should be close to 1000 seconds (allow for test execution time)
      assert seconds >= 999 and seconds <= 1000
    end

    test "returns 0 for expired session (not negative)" do
      past_time = System.os_time(:second) - 500

      session = session_fixture(%{expires_at: past_time})

      assert Session.seconds_until_expiry(session) == 0
    end

    test "returns 0 when expiry is exactly now" do
      current_time = System.os_time(:second)

      session = session_fixture(%{expires_at: current_time})

      assert Session.seconds_until_expiry(session) == 0
    end
  end

  describe "refresh_if_needed/3" do
    test "returns original session when not expiring and not forced", %{client: client} do
      # Session expires in 1 hour (beyond 5 minute default margin)
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          expires_at: future_time,
          refresh_token: "valid-refresh-token"
        })

      assert {:ok, ^session} = Auth.refresh_if_needed(client, session)
    end

    test "refreshes session when expiring soon (within default margin)", %{client: client, json: json} do
      # Session expires in 2 minutes (within 5 minute margin)
      near_future = System.os_time(:second) + 120
      new_future = System.os_time(:second) + 3600

      old_session =
        session_fixture(%{
          expires_at: near_future,
          access_token: "old-access-token",
          refresh_token: "refresh-token"
        })

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"
        assert Request.get_query_param(req, "grant_type") == "refresh_token"

        user = [id: "123"] |> user_fixture() |> Map.from_struct()

        body =
          session_fixture_json(
            access_token: "new-access-token",
            refresh_token: "new-refresh-token",
            expires_at: new_future,
            user: user
          )

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.refresh_if_needed(client, old_session)
      assert refreshed.access_token == "new-access-token"
      assert refreshed.expires_at == new_future
    end

    test "refreshes session when already expired", %{client: client, json: json} do
      past_time = System.os_time(:second) - 100
      new_future = System.os_time(:second) + 3600

      old_session =
        session_fixture(%{
          expires_at: past_time,
          access_token: "expired-token",
          refresh_token: "refresh-token"
        })

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "new-token", expires_at: new_future, user: user)

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.refresh_if_needed(client, old_session)
      assert refreshed.access_token == "new-token"
    end

    test "respects custom :within option", %{client: client, json: json} do
      # Session expires in 2 minutes
      expiry_time = System.os_time(:second) + 120
      new_future = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          expires_at: expiry_time,
          refresh_token: "refresh-token"
        })

      # With 1 minute margin: should NOT refresh
      assert {:ok, ^session} = Auth.refresh_if_needed(client, session, within: 60)

      # With 3 minute margin: should refresh
      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "new-token", expires_at: new_future, user: user)

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.refresh_if_needed(client, session, within: 180)
      assert refreshed.access_token == "new-token"
    end

    test "forces refresh even when session is fresh with :force option", %{client: client, json: json} do
      # Fresh session (expires in 1 hour)
      future_time = System.os_time(:second) + 3600

      old_session =
        session_fixture(%{
          expires_at: future_time,
          access_token: "old-token",
          refresh_token: "refresh-token"
        })

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post

        user = [id: "123"] |> user_fixture() |> Map.from_struct()

        body =
          session_fixture_json(
            access_token: "forced-new-token",
            expires_at: future_time + 3600,
            user: user
          )

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.refresh_if_needed(client, old_session, force: true)
      assert refreshed.access_token == "forced-new-token"
    end

    test "returns error when refresh fails", %{client: client} do
      near_future = System.os_time(:second) + 120

      session =
        session_fixture(%{
          expires_at: near_future,
          refresh_token: "invalid-refresh-token"
        })

      expect(@mock, :request, fn %Request{} = _req, _opts ->
        {:ok,
         %Finch.Response{
           status: 401,
           body: ~s({"error":"invalid_grant","error_description":"Invalid refresh token"}),
           headers: []
         }}
      end)

      assert {:error, %Supabase.Error{}} = Auth.refresh_if_needed(client, session)
    end

    test "handles session with nil expires_at", %{client: client} do
      session =
        session_fixture(%{
          expires_at: nil,
          refresh_token: "refresh-token"
        })

      # Should not refresh (nil expires_at means never expires)
      assert {:ok, ^session} = Auth.refresh_if_needed(client, session)
    end
  end

  describe "ensure_valid_session/3" do
    test "returns original session when valid and not expiring", %{client: client} do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: "valid-refresh",
          expires_at: future_time
        })

      assert {:ok, ^session} = Auth.ensure_valid_session(client, session)
    end

    test "returns error when session has no access_token", %{client: client} do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: nil,
          refresh_token: "valid-refresh",
          expires_at: future_time
        })

      assert {:error, :invalid_session} = Auth.ensure_valid_session(client, session)
    end

    test "returns error when session has no refresh_token", %{client: client} do
      future_time = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: "valid-token",
          refresh_token: nil,
          expires_at: future_time
        })

      assert {:error, :invalid_session} = Auth.ensure_valid_session(client, session)
    end

    test "returns error when session is already expired and has no tokens", %{client: client} do
      past_time = System.os_time(:second) - 100

      session =
        session_fixture(%{
          access_token: nil,
          refresh_token: nil,
          expires_at: past_time
        })

      assert {:error, :invalid_session} = Auth.ensure_valid_session(client, session)
    end

    test "refreshes session when expiring soon", %{client: client, json: json} do
      near_future = System.os_time(:second) + 120
      new_future = System.os_time(:second) + 3600

      old_session =
        session_fixture(%{
          access_token: "old-token",
          refresh_token: "refresh-token",
          expires_at: near_future
        })

      expect(@mock, :request, fn %Request{} = req, _opts ->
        assert req.method == :post
        user = [id: "123"] |> user_fixture() |> Map.from_struct()

        body =
          session_fixture_json(
            access_token: "new-token",
            refresh_token: "new-refresh",
            expires_at: new_future,
            user: user
          )

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.ensure_valid_session(client, old_session)
      assert refreshed.access_token == "new-token"
      assert Session.valid?(refreshed)
      refute Session.needs_refresh?(refreshed)
    end

    test "returns error when refresh fails", %{client: client} do
      near_future = System.os_time(:second) + 120

      session =
        session_fixture(%{
          access_token: "old-token",
          refresh_token: "invalid-refresh",
          expires_at: near_future
        })

      expect(@mock, :request, fn %Request{} = _req, _opts ->
        {:ok,
         %Finch.Response{
           status: 401,
           body: ~s({"error":"invalid_grant"}),
           headers: []
         }}
      end)

      assert {:error, :refresh_failed} = Auth.ensure_valid_session(client, session)
    end

    test "respects custom :within option", %{client: client, json: json} do
      # Expires in 2 minutes
      expiry_time = System.os_time(:second) + 120
      new_future = System.os_time(:second) + 3600

      session =
        session_fixture(%{
          access_token: "token",
          refresh_token: "refresh",
          expires_at: expiry_time
        })

      # With 1 minute margin: should NOT refresh (session still valid)
      assert {:ok, ^session} = Auth.ensure_valid_session(client, session, within: 60)

      # With 3 minute margin: should refresh
      expect(@mock, :request, fn %Request{} = _req, _opts ->
        user = [id: "123"] |> user_fixture() |> Map.from_struct()
        body = session_fixture_json(access_token: "new-token", expires_at: new_future, user: user)

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      assert {:ok, refreshed} = Auth.ensure_valid_session(client, session, within: 180)
      assert refreshed.access_token == "new-token"
    end

    test "handles session with nil expires_at", %{client: client} do
      session =
        session_fixture(%{
          access_token: "token",
          refresh_token: "refresh",
          expires_at: nil
        })

      # Should return original session (valid, never expires)
      assert {:ok, ^session} = Auth.ensure_valid_session(client, session)
    end
  end
end
