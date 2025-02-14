defmodule Supabase.GoTrueTest do
  use ExUnit.Case, async: true

  import Mox

  import Supabase.GoTrue.SessionFixture
  import Supabase.GoTrue.UserFixture

  alias Supabase.GoTrue
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  alias Supabase.Fetcher.Request

  setup :verify_on_exit!

  @mock TestHTTPClient

  setup_all do
    Application.put_env(:supabase_gotrue, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_gotrue, :http_client)
    end)
  end

  setup do
    client = Supabase.init_client!("https://localhost:54321", "test-api-key")

    {:ok, client: client}
  end

  describe "get_user/2" do
    test "successfully retrieves an existing user", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{status: 200, body: body, headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert {:ok, %User{} = user} = GoTrue.get_user(client, session)
      assert user.id == "123"
    end

    test "returns an error when user doesn't exists", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        {:ok, %Finch.Response{status: 404, body: "{}", headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert {:error, %Supabase.Error{}} = GoTrue.get_user(client, session)
    end

    test "returns an unexpected error", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/user"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      session = %Session{access_token: "123"}
      assert {:error, %Supabase.Error{}} = GoTrue.get_user(client, session)
    end
  end

  describe "sign_in_with_id_token/2" do
    test "successfully sings in an user with ID token", %{client: client} do
      data = %{provider: :apple, token: "123"}

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = Jason.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        user = user_fixture(id: "123") |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = GoTrue.sign_in_with_id_token(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on authentication error", %{client: client} do
      data = %{provider: :apple, token: "123"}

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = Jason.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = GoTrue.sign_in_with_id_token(client, data)
    end

    test "returns an error on unexpected error", %{client: client} do
      data = %{provider: :apple, token: "123"}

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "id_token" => "123",
                 "provider" => "apple"
               } = Jason.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "id_token"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} = GoTrue.sign_in_with_id_token(client, data)
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

      assert {:ok, :github, %URI{} = url} = GoTrue.sign_in_with_oauth(client, data)
      assert url.path =~ "/authorize"
      assert url.query =~ "state=123"
      assert url.query =~ "scopes=user%3Aemail+read%3Auser"
    end
  end

  describe "sign_in_with_otp/2" do
    test "successfully triggers an user signin with email OTP", %{client: client} do
      data = %{
        email: "john@example.com",
        options: %{
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "create_user" => true,
                 "email" => "john@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => "123"}
               } = Jason.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      # user should receive an OTP code via email
      assert :ok = GoTrue.sign_in_with_otp(client, data)
    end

    test "successfully triggers an user signin with phone OTP", %{client: client} do
      data = %{
        phone: "+5522123456789",
        options: %{
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "channel" => "sms",
                 "create_user" => true,
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "phone" => "+5522123456789"
               } = Jason.decode!(req.body)

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
      assert {:ok, message_id} = GoTrue.sign_in_with_otp(client, data)
      assert message_id == "123"
    end

    test "successfully triggers an user signin with whatsapp OTP", %{client: client} do
      data = %{
        phone: "+5522123456789",
        options: %{
          channel: "whatsapp",
          captcha_token: "123",
          should_create_user: true,
          redirect_to: "http://localhost:3000"
        }
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/otp"

        assert %{
                 "channel" => "whatsapp",
                 "create_user" => true,
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "phone" => "+5522123456789"
               } = Jason.decode!(req.body)

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
      assert {:ok, message_id} = GoTrue.sign_in_with_otp(client, data)
      assert message_id == "123"
    end
  end

  describe "verify_otp/2" do
    test "successfully verifies an email OTP code", %{client: client} do
      for type <- ~w[signup invite magiclink recovery email_change email]a do
        data = %{
          email: "john@example.com",
          token: "123",
          type: type,
          options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
        }

        @mock
        |> expect(:request, fn %Request{} = req, _opts ->
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
                 } = Jason.decode!(req.body)

          assert t == Atom.to_string(type)

          user = user_fixture(id: "123") |> Map.from_struct()
          body = session_fixture_json(access_token: "123", user: user)

          {:ok, %Finch.Response{status: 201, body: body, headers: []}}
        end)

        assert {:ok, %Session{} = session} = GoTrue.verify_otp(client, data)
        assert session.access_token == "123"
        assert session.user.id == "123"
      end
    end

    test "successfully verifies phone OTP code", %{client: client} do
      for type <- ~w[sms phone_change]a do
        data = %{
          phone: "+5522123456789",
          token: "123",
          type: type,
          options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
        }

        @mock
        |> expect(:request, fn %Request{} = req, _opts ->
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
                 } = Jason.decode!(req.body)

          assert t == Atom.to_string(type)

          user = user_fixture(id: "123") |> Map.from_struct()
          body = session_fixture_json(access_token: "123", user: user)

          {:ok, %Finch.Response{status: 201, body: body, headers: []}}
        end)

        assert {:ok, %Session{} = session} = GoTrue.verify_otp(client, data)
        assert session.access_token == "123"
        assert session.user.id == "123"
      end
    end

    test "successfully verifies a token hash OTP code", %{client: client} do
      data = %{
        token_hash: "123",
        type: :signup,
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
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
               } = Jason.decode!(req.body)

        user = user_fixture(id: "123") |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = GoTrue.verify_otp(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on unauthenticated", %{client: client} do
      data = %{
        email: "john@example.com",
        token: "123",
        type: :email,
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
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
               } = Jason.decode!(req.body)

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = GoTrue.verify_otp(client, data)
    end
  end

  describe "sign_in_with_sso/2" do
    test "successfully signin an user with SSO", %{client: client} do
      data = %{
        provider_id: "apple",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/sso"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "provider_id" => "apple"
               } = Jason.decode!(req.body)

        body = """
        {
          "data": {
            "url": "http://localhost:3000"
          }
        }
        """

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, "http://localhost:3000"} = GoTrue.sign_in_with_sso(client, data)
    end
  end

  describe "sign_in_with_password/2" do
    test "successfully signs in an user with email and password", %{client: client} do
      data = %{
        email: "john@example.com",
        password: "123",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "email" => "john@example.com",
                 "password" => "123"
               } = Jason.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "password"

        user = user_fixture(id: "123") |> Map.from_struct()
        body = session_fixture_json(access_token: "123", user: user)

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %Session{} = session} = GoTrue.sign_in_with_password(client, data)
      assert session.access_token == "123"
      assert session.user.id == "123"
    end

    test "returns an error on authentication error", %{client: client} do
      data = %{
        email: "john@example.com",
        password: "123",
        options: %{captcha_token: "123", redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/token"

        assert %{
                 "data" => %{},
                 "gotrue_meta_security" => %{"captcha_token" => "123"},
                 "email" => "john@example.com",
                 "password" => "123"
               } = Jason.decode!(req.body)

        assert Request.get_query_param(req, "grant_type") == "password"

        {:ok, %Finch.Response{status: 401, body: "{}", headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = GoTrue.sign_in_with_password(client, data)
    end
  end

  describe "sign_up/2" do
    test "successfully signs up an user with email and password", %{client: client} do
      data = %{
        email: "another@example.com",
        password: "123",
        phone: "+5522123456789",
        options: %{captcha_token: "123", email_redirect_to: "http://localhost:3000"}
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
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
               } = Jason.decode!(req.body)

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{status: 201, body: body, headers: []}}
      end)

      assert {:ok, %User{} = user} = GoTrue.sign_up(client, data)
      assert user.id == "123"
    end
  end

  describe "reset_password_for_email/3" do
    test "successfully sends a recovery password email", %{client: client} do
      email = "another@example.com"

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/recover"

        assert %{
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => nil}
               } = Jason.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      assert :ok =
               GoTrue.reset_password_for_email(client, email,
                 redirect_to: "http://localhost:3000"
               )
    end

    test "returns an error on unexpected error", %{client: client} do
      email = "another@example.com"

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/recover"

        {:error, %Mint.TransportError{reason: :timeout}}
      end)

      assert {:error, %Supabase.Error{}} =
               GoTrue.reset_password_for_email(client, email,
                 redirect_to: "http://localhost:3000"
               )
    end
  end

  describe "resend/3" do
    test "successfully resends a signup confirm email", %{client: client} do
      email = "another@example.com"

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/resend"

        assert %{
                 "email" => "another@example.com",
                 "gotrue_meta_security" => %{"captcha_token" => nil},
                 "type" => "signup"
               } = Jason.decode!(req.body)

        {:ok, %Finch.Response{status: 200, body: "{}", headers: []}}
      end)

      assert :ok =
               GoTrue.resend(client, email, redirect_to: "http://localhost:3000", type: :signup)
    end
  end
end
