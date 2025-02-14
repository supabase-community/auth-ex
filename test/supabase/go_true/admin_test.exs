defmodule Supabase.GoTrue.AdminTest do
  use ExUnit.Case, async: true

  import Mox

  import Supabase.GoTrue.UserFixture
  import Supabase.GoTrue.Admin.UserFixture
  import Supabase.GoTrue.Admin.LinkFixture

  alias Supabase.GoTrue.Admin
  alias Supabase.GoTrue.Session
  alias Supabase.GoTrue.User

  alias Supabase.Fetcher.Request

  setup :verify_on_exit!

  @mock TestHTTPClient

  setup do
    client = Supabase.init_client!("http://localhost:54321", "test-api-key")
    Application.put_env(:supabase_gotrue, :http_client, @mock)

    on_exit(fn ->
      Application.delete_env(:supabase_gotrue, :http_client)
    end)

    {:ok, client: client}
  end

  describe "sign_out/3" do
    test "successfully signs out an user", %{client: client} do
      scope = :global

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/logout"
        assert req.url.query =~ "scope=#{scope}"

        {:ok, %Finch.Response{body: ~s|{}|, status: 201, headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert :ok = Admin.sign_out(client, session, scope)
    end

    test "interpret missing session as successfully signed out", %{client: client} do
      scope = :global

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/logout"
        assert req.url.query =~ "scope=#{scope}"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      session = %Session{access_token: nil}
      assert :ok = Admin.sign_out(client, session, scope)
    end

    test "interpret unauthenticated session as successfully signed out", %{client: client} do
      scope = :global

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/logout"
        assert req.url.query =~ "scope=#{scope}"

        {:ok, %Finch.Response{body: ~s|{}|, status: 401, headers: []}}
      end)

      session = %Session{access_token: "123"}
      assert :ok = Admin.sign_out(client, session, scope)
    end

    test "unexpected error is returned", %{client: client} do
      scope = :global

      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      session = %Session{access_token: "123"}

      assert {:error, %Supabase.Error{} = err} = Admin.sign_out(client, session, scope)
      assert err.code == :unexpected
    end
  end

  describe "invite_user_by_email/3" do
    test "successfully invites an user with no custom options", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/invite"

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %User{} = user} = Admin.invite_user_by_email(client, "john@example.com")
      assert user.id == "123"
    end

    test "successfully invites an user with custom options", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/invite"
        assert Request.get_header(req, "redirect_to") =~ "http://example.com"

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %User{} = user} =
               Admin.invite_user_by_email(client, "john@example.com", %{
                 data: %{custom: "hello"},
                 redirect_to: "http://example.com/confirmar"
               })

      assert user.id == "123"
    end

    test "invalid custom options should return an error", %{client: client} do
      assert {:error, %Supabase.Error{}} =
               Admin.invite_user_by_email(client, "john@example.com", %{
                 data: %{custom: "hello", redirect_to: 123}
               })
    end

    test "unexpected error should be returned", %{client: client} do
      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} =
               Admin.invite_user_by_email(client, "john@example.com")
    end
  end

  describe "generate_link/2" do
    test "successfully generates a link for signup", %{client: client} do
      data = %{
        type: "signup",
        email: "john@example.com",
        password: "123456",
        redirect_to: "http://example.com/confirmar"
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/generate_link"

        body = link_fixture_json(email_otp: "123456", verification_type: "signup")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %{} = props} = Admin.generate_link(client, data)
      assert props.email_otp == "123456"
      assert props.verification_type == :signup
    end

    test "returns an error when generates an invalid link for signup", %{client: client} do
      data = %{
        type: "signup",
        email: 123,
        password: "123456",
        redirect_to: "http://example.com/confirmar"
      }

      assert {:error, %Ecto.Changeset{}} = Admin.generate_link(client, data)
    end

    test "successfully generates a link for invite or magicLink", %{client: client} do
      data = %{
        type: "invite",
        email: "john@example.com",
        redirect_to: "http://example.com/confirmar"
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/generate_link"

        body = link_fixture_json(email_otp: "123456", verification_type: "invite")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %{} = props} = Admin.generate_link(client, data)
      assert props.email_otp == "123456"
      assert props.verification_type == :invite
    end

    test "returns an error when generates an invalid link for invite or magicLink", %{
      client: client
    } do
      data = %{
        type: "magicLink",
        email: 123,
        redirect_to: "http://example.com/confirmar"
      }

      assert {:error, %Ecto.Changeset{}} = Admin.generate_link(client, data)
    end

    test "successfully generates a link for recovery", %{client: client} do
      data = %{
        type: "recovery",
        email: "john@example.com",
        redirect_to: "http://example.com/confirmar"
      }

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/generate_link"

        body = link_fixture_json(email_otp: "123456", verification_type: "recovery")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %{} = props} = Admin.generate_link(client, data)
      assert props.email_otp == "123456"
      assert props.verification_type == :recovery
    end

    test "returns an error when generates an invalid link recovery", %{
      client: client
    } do
      data = %{
        type: "recovery",
        email: 123,
        redirect_to: "http://example.com/confirmar"
      }

      assert {:error, %Ecto.Changeset{}} = Admin.generate_link(client, data)
    end

    test "successfully generates a link for email change", %{client: client} do
      for type <- [:email_change_current, :email_change_new] do
        data = %{
          type: Atom.to_string(type),
          email: "john@example.com",
          redirect_to: "http://example.com/confirmar"
        }

        @mock
        |> expect(:request, fn %Request{} = req, _opts ->
          assert req.method == :post
          assert req.url.path =~ "/admin/generate_link"

          body = link_fixture_json(email_otp: "123456", verification_type: Atom.to_string(type))

          {:ok, %Finch.Response{body: body, status: 201, headers: []}}
        end)

        assert {:ok, %{} = props} = Admin.generate_link(client, data)
        assert props.email_otp == "123456"
        assert props.verification_type == type
      end
    end

    test "returns an error when generates an invalid link email change", %{
      client: client
    } do
      for type <- [:email_change_current, :email_change_new] do
        data = %{
          type: Atom.to_string(type),
          email: 123,
          redirect_to: "http://example.com/confirmar"
        }

        assert {:error, %Ecto.Changeset{}} = Admin.generate_link(client, data)
      end
    end
  end

  describe "create_user/2" do
    test "successfully creates an user", %{client: client} do
      data = user_create_fixture(email: "john@example.com")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :post
        assert req.url.path =~ "/admin/users"

        body = user_fixture_json(id: "123", email: "john@example.com")

        {:ok, %Finch.Response{body: body, status: 201, headers: []}}
      end)

      assert {:ok, %User{} = user} = Admin.create_user(client, data)
      assert user.id == "123"
      assert user.email == "john@example.com"
    end

    test "returns an error when creates an invalid user", %{client: client} do
      data = user_create_fixture(email: 123)

      assert {:error, %Ecto.Changeset{}} = Admin.create_user(client, data)
    end

    test "unexpected error is returned", %{client: client} do
      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      data = user_create_fixture(email: "john@example.com")
      assert {:error, %Supabase.Error{}} = Admin.create_user(client, data)
    end
  end

  describe "delete_user/3" do
    test "successfully deletes an user", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/users/123"

        {:ok, %Finch.Response{body: ~s|{}|, status: 204, headers: []}}
      end)

      assert :ok = Admin.delete_user(client, user.id)
    end

    test "successfully soft deletes an user", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/users/123"
        assert req.body == Jason.encode_to_iodata!(%{should_soft_delete: true})

        {:ok, %Finch.Response{body: ~s|{}|, status: 204, headers: []}}
      end)

      assert :ok = Admin.delete_user(client, user.id, should_soft_delete: true)
    end

    test "returns an error when user doesn't exist", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :delete
        assert req.url.path =~ "/admin/users/123"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.delete_user(client, user.id)
    end

    test "returns an unexpected error", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.delete_user(client, user.id)
    end
  end

  describe "get_user_by_id/2" do
    test "successfully gets an user", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/users/123"

        body = user_fixture_json(id: "123")

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, %User{} = user} = Admin.get_user_by_id(client, user.id)
      assert user.id == "123"
    end

    test "returns an error when user doesn't exist", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/users/123"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.get_user_by_id(client, user.id)
    end

    test "returns an unexpected error", %{client: client} do
      user = user_fixture(id: "123")

      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.get_user_by_id(client, user.id)
    end
  end

  describe "list_users/2" do
    test "successfully list users without custom pagination options", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/users"

        body = %{users: for(i <- 1..10, do: user_fixture(id: Integer.to_string(i)))}

        {:ok,
         %Finch.Response{
           body: Jason.encode!(body),
           status: 200,
           headers: [
             {"x-total-count", "10"},
             {"link", "</admin/users?page=0&per_page=>; rel=\"last\""}
           ]
         }}
      end)

      assert {:ok, users, pagination} = Admin.list_users(client)
      assert length(users) == 10
      assert pagination.total == 10
      assert pagination.last_page == 0
      refute pagination[:next_page]
    end

    test "successfully list users with custom pagination options", %{client: client} do
      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :get
        assert req.url.path =~ "/admin/users"
        assert Request.get_query_param(req, "page") == "2"
        assert per_page = Request.get_query_param(req, "per_page")
        assert (per_page = String.to_integer(per_page)) == 5

        body = %{users: for(i <- 1..per_page, do: user_fixture(id: Integer.to_string(i)))}

        {:ok,
         %Finch.Response{
           body: Jason.encode!(body),
           status: 200,
           headers: [
             {"x-total-count", "10"},
             {"link", "</admin/users?page=2&per_page=5; rel=\"last\""}
           ]
         }}
      end)

      assert {:ok, users, pagination} = Admin.list_users(client, page: 2, per_page: 5)
      assert length(users) == 5
      assert pagination.total == 10
      assert pagination.last_page == 2
      refute pagination[:next_page]
    end

    test "returns an unexpected error", %{client: client} do
      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.list_users(client)
    end
  end

  describe "update_user_by_id/3" do
    test "successfully updates an existing user", %{client: client} do
      user = user_fixture(id: "123")
      data = %{email: "another@example.com"}

      assert user.email != data.email

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/users/123"

        body = user_fixture_json(id: "123", email: "another@example.com")

        {:ok, %Finch.Response{body: body, status: 200, headers: []}}
      end)

      assert {:ok, %User{} = user} = Admin.update_user_by_id(client, user.id, data)
      assert user.id == "123"
      assert user.email == "another@example.com"
    end

    test "returns an error when user doesn't exist", %{client: client} do
      user = user_fixture(id: "123")
      data = %{email: "another@example.com"}

      @mock
      |> expect(:request, fn %Request{} = req, _opts ->
        assert req.method == :put
        assert req.url.path =~ "/admin/users/123"

        {:ok, %Finch.Response{body: ~s|{}|, status: 404, headers: []}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.update_user_by_id(client, user.id, data)
    end

    test "returns an error when user data is invalid", %{client: client} do
      user = user_fixture(id: "123")
      data = %{email: 123}

      assert {:error, %Ecto.Changeset{}} = Admin.update_user_by_id(client, user.id, data)
    end

    test "returns an unexpected error", %{client: client} do
      user = user_fixture(id: "123")
      data = %{email: "another@example.com"}

      @mock
      |> expect(:request, fn %Request{}, _opts ->
        {:error, %Mint.TransportError{reason: :closed}}
      end)

      assert {:error, %Supabase.Error{}} = Admin.update_user_by_id(client, user.id, data)
    end
  end
end
