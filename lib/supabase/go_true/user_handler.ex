defmodule Supabase.GoTrue.UserHandler do
  @moduledoc false

  alias Phoenix.LiveView.Socket
  alias Supabase.Client
  alias Supabase.Fetcher
  alias Supabase.Fetcher.Request
  alias Supabase.GoTrue
  alias Supabase.GoTrue.PKCE
  alias Supabase.GoTrue.Schemas.ResendParams
  alias Supabase.GoTrue.Schemas.SignInAnonymously
  alias Supabase.GoTrue.Schemas.SignInRequest
  alias Supabase.GoTrue.Schemas.SignInWithIdToken
  alias Supabase.GoTrue.Schemas.SignInWithOauth
  alias Supabase.GoTrue.Schemas.SignInWithOTP
  alias Supabase.GoTrue.Schemas.SignInWithPassword
  alias Supabase.GoTrue.Schemas.SignInWithSSO
  alias Supabase.GoTrue.Schemas.SignUpRequest
  alias Supabase.GoTrue.Schemas.SignUpWithPassword
  alias Supabase.GoTrue.Schemas.VerifyOTP
  alias Supabase.GoTrue.User

  @single_user_uri "/user"
  @sign_in_uri "/token"
  @sign_up_uri "/signup"
  @oauth_uri "/authorize"
  @sso_uri "/sso"
  @otp_uri "/otp"
  @verify_otp_uri "/verify"
  @reset_pass_uri "/recover"
  @resend_signup_uri "/resend"
  @settings_uri "/settings"
  @health_uri "/health"
  @identities_uri "/identities"
  @identity_authorize_uri "/identities/authorize"
  @token_uri "/token"

  def get_user(%Client{} = client, access_token) when is_binary(access_token) do
    client
    |> GoTrue.Request.base(@single_user_uri)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Fetcher.request()
  end

  def verify_otp(%Client{} = client, %{} = params) do
    with {:ok, body} <- VerifyOTP.to_request(params) do
      client
      |> GoTrue.Request.base(@verify_otp_uri)
      |> Request.with_query(%{"redirect_to" => get_in(body, [:options, :redirect_to])})
      |> Request.with_method(:post)
      |> Request.with_body(body)
      |> Fetcher.request()
    end
  end

  def sign_in_with_otp(%Client{} = client, %SignInWithOTP{} = signin) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()

    with {:ok, body} <- SignInRequest.create(signin, challenge, method) do
      client
      |> GoTrue.Request.base(@otp_uri)
      |> Request.with_body(body)
      |> Request.with_method(:post)
      |> Request.with_query(%{"redirect_to" => body.redirect_to})
      |> Fetcher.request()
      |> then(fn
        {:ok, resp} ->
          if is_nil(signin.email), do: {:ok, resp.body["data"]["message_id"]}, else: :ok

        err ->
          err
      end)
    end
  end

  def sign_in_with_otp(%Client{} = client, %SignInWithOTP{} = signin) do
    with {:ok, body} <- SignInRequest.create(signin) do
      client
      |> GoTrue.Request.base(@otp_uri)
      |> Request.with_body(body)
      |> Request.with_method(:post)
      |> Request.with_query(%{"redirect_to" => body.redirect_to})
      |> Fetcher.request()
      |> then(fn
        {:ok, resp} ->
          if is_nil(signin.email), do: {:ok, resp.body["data"]["message_id"]}, else: :ok

        err ->
          err
      end)
    end
  end

  def sign_in_with_sso(%Client{} = client, %SignInWithSSO{} = signin) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()

    with {:ok, body} <- SignInRequest.create(signin, challenge, method) do
      client
      |> GoTrue.Request.base(@sso_uri)
      |> Request.with_body(body)
      |> Request.with_method(:post)
      |> Request.with_query(%{"redirect_to" => body.redirect_to})
      |> Fetcher.request()
      |> then(fn
        {:ok, resp} -> {:ok, resp["data"]["url"]}
        err -> err
      end)
    end
  end

  def sign_in_with_sso(%Client{} = client, %SignInWithSSO{} = signin) do
    with {:ok, body} <- SignInRequest.create(signin) do
      client
      |> GoTrue.Request.base(@sso_uri)
      |> Request.with_body(body)
      |> Request.with_method(:post)
      |> Request.with_query(%{"redirect_to" => body.redirect_to})
      |> Fetcher.request()
      |> then(fn
        {:ok, resp} -> {:ok, resp.body["data"]["url"]}
        err -> err
      end)
    end
  end

  def sign_in_anonymously(%Client{} = client, %SignInAnonymously{} = opts) do
    client
    |> GoTrue.Request.base(@sign_up_uri)
    |> Request.with_method(:post)
    |> Request.with_body(%{"options" => opts})
    |> Fetcher.request()
  end

  @grant_types ~w[password id_token]

  def sign_in_with_password(%Client{} = client, %SignInWithPassword{} = signin) do
    with {:ok, request} <- SignInRequest.create(signin) do
      sign_in_request(client, request, "password")
    end
  end

  def sign_in_with_id_token(%Client{} = client, %SignInWithIdToken{} = signin) do
    with {:ok, request} <- SignInRequest.create(signin) do
      sign_in_request(client, request, "id_token")
    end
  end

  defp sign_in_request(%Client{} = client, %SignInRequest{} = body, grant_type) when grant_type in @grant_types do
    client
    |> GoTrue.Request.base(@sign_in_uri)
    |> Request.with_method(:post)
    |> Request.with_body(body)
    |> Request.with_query(%{
      "grant_type" => grant_type,
      "redirect_to" => body.redirect_to
    })
    |> Fetcher.request()
  end

  def sign_up(%Client{} = client, %SignUpWithPassword{} = signup) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()

    with {:ok, body} <- SignUpRequest.create(signup, challenge, method),
         {:ok, resp} <-
           client
           |> GoTrue.Request.base(@sign_up_uri)
           |> Request.with_method(:post)
           |> Request.with_body(body)
           |> Fetcher.request(),
         {:ok, user} <- User.parse(resp.body) do
      {:ok, user, challenge}
    end
  end

  def sign_up(%Client{} = client, %SignUpWithPassword{} = signup) do
    with {:ok, body} <- SignUpRequest.create(signup),
         {:ok, resp} <-
           client
           |> GoTrue.Request.base(@sign_up_uri)
           |> Request.with_method(:post)
           |> Request.with_body(body)
           |> Fetcher.request() do
      User.parse(resp.body)
    end
  end

  def recover_password(%Client{} = client, email, %{} = opts) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()

    body = %{
      email: email,
      code_challenge: challenge,
      code_challenge_method: method,
      go_true_meta_security: %{captcha_token: opts[:captcha_token]}
    }

    builder =
      client
      |> GoTrue.Request.base(@reset_pass_uri)
      |> Request.with_method(:post)
      |> Request.with_body(body)
      |> Request.with_query(%{"redirect_to" => opts[:redirect_to]})

    with {:ok, _} <- Fetcher.request(builder), do: :ok
  end

  def recover_password(%Client{} = client, email, %{} = opts) do
    body = %{
      email: email,
      gotrue_meta_security: %{captcha_token: opts[:captcha_token]}
    }

    builder =
      client
      |> GoTrue.Request.base(@reset_pass_uri)
      |> Request.with_method(:post)
      |> Request.with_body(body)
      |> Request.with_query(%{"redirect_to" => opts[:redirect_to]})

    with {:ok, _} <- Fetcher.request(builder), do: :ok
  end

  def resend(%Client{} = client, email, %ResendParams{} = opts) do
    body = %{
      email: email,
      type: opts.type,
      gotrue_meta_security: %{captcha_token: get_in(opts.options.captcha_token)}
    }

    builder =
      client
      |> GoTrue.Request.base(@resend_signup_uri)
      |> Request.with_method(:post)
      |> Request.with_body(body)
      |> Request.with_query(%{"redirect_to" => get_in(opts.options.redirect_to)})

    with {:ok, _} <- Fetcher.request(builder), do: :ok
  end

  def update_user(%Client{} = client, conn, %{} = params) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()

    access_token =
      case conn do
        %Plug.Conn{} -> Plug.Conn.get_session(conn, :user_token)
        %Socket{} -> conn.assigns.user_token
      end

    body = Map.merge(params, %{code_challenge: challenge, code_challenge_method: method})

    builder =
      client
      |> GoTrue.Request.base(@single_user_uri)
      |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
      |> Request.with_method(:post)
      |> Request.with_body(body)
      |> Request.with_query(%{"redirect_to" => params[:email_redirect_to]})

    session = %{"user_token" => access_token}
    auth_module = Supabase.GoTrue.get_auth_module!()

    with {:ok, _} <- Fetcher.request(builder) do
      case conn do
        %Plug.Conn{} ->
          {:ok, auth_module.fetch_current_user(conn, nil)}

        %Socket{} ->
          {:ok, auth_module.mount_current_user(session, conn)}
      end
    end
  end

  def update_user(%Client{} = client, conn, %{} = params) do
    access_token =
      case conn do
        %Plug.Conn{} -> Plug.Conn.get_session(conn, :user_token)
        %Socket{} -> conn.assigns.user_token
      end

    builder =
      client
      |> GoTrue.Request.base(@single_user_uri)
      |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
      |> Request.with_method(:post)
      |> Request.with_body(params)
      |> Request.with_query(%{"redirect_to" => params[:email_redirect_to]})

    session = %{"user_token" => access_token}
    auth_module = Supabase.GoTrue.get_auth_module!()

    with {:ok, _} <- Fetcher.request(builder) do
      case conn do
        %Plug.Conn{} ->
          {:ok, auth_module.fetch_current_user(conn, nil)}

        %Socket{} ->
          {:ok, auth_module.mount_current_user(session, conn)}
      end
    end
  end

  def get_url_for_provider(%Client{} = client, %SignInWithOauth{} = oauth) when client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()
    pkce_query = %{code_challenge: challenge, code_challenge_method: method}
    oauth_query = SignInWithOauth.options_to_query(oauth)
    query = pkce_query |> Map.merge(oauth_query) |> Map.new(fn {k, v} -> {to_string(k), v} end)

    client
    |> GoTrue.Request.base(@oauth_uri)
    |> Request.with_query(query)
    |> then(fn %{query: query, url: url} ->
      query = URI.encode_query(query)
      URI.append_query(url, query)
    end)
  end

  def get_url_for_provider(%Client{} = client, %SignInWithOauth{} = oauth) do
    oauth_query = SignInWithOauth.options_to_query(oauth)
    query = Map.new(oauth_query, fn {k, v} -> {to_string(k), v} end)

    client
    |> GoTrue.Request.base(@oauth_uri)
    |> Request.with_query(query)
    |> then(fn %{query: query, url: url} ->
      query = URI.encode_query(query)
      URI.append_query(url, query)
    end)
  end

  def refresh_session(%Client{} = client, refresh_token) when is_binary(refresh_token) do
    client
    |> GoTrue.Request.base(@sign_in_uri)
    |> Request.with_query(%{"grant_type" => "refresh_token"})
    |> Request.with_method(:post)
    |> Request.with_body(%{"refresh_token" => refresh_token})
    |> Fetcher.request()
  end

  def get_server_settings(%Client{} = client) do
    client
    |> GoTrue.Request.base(@settings_uri)
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  def get_server_health(%Client{} = client) do
    client
    |> GoTrue.Request.base(@health_uri)
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  defp generate_pkce do
    verifier = PKCE.generate_verifier()
    challenge = PKCE.generate_challenge(verifier)
    method = if verifier == challenge, do: "plain", else: "s256"
    {challenge, method}
  end

  @doc """
  Exchanges an authorization code for a session.

  Used in the PKCE (Proof Key for Code Exchange) flow to convert an authorization code
  into a valid session using a code_verifier that matches the previously sent code_challenge.

  ## Parameters
    * `client` - The `Supabase` client to use for the request.
    * `auth_code` - The authorization code received from the OAuth provider.
    * `code_verifier` - The original code verifier that was used to generate the code challenge.
    * `opts` - Additional options:
      * `redirect_to` - The URL to redirect to after successful authentication.
  """
  def exchange_code_for_session(%Client{} = client, auth_code, code_verifier, opts \\ %{}) do
    body = %{
      auth_code: auth_code,
      code_verifier: code_verifier,
      redirect_to: opts[:redirect_to]
    }

    client
    |> GoTrue.Request.base(@token_uri)
    |> Request.with_method(:post)
    |> Request.with_body(body)
    |> Request.with_query(%{
      "grant_type" => "pkce"
    })
    |> Fetcher.request()
  end

  @doc """
  Get a URL to link a new identity to the user's account.

  This endpoint requires authentication.
  """
  def link_identity(%Client{} = client, access_token, %SignInWithOauth{} = oauth)
      when is_binary(access_token) and client.auth.flow_type == :pkce do
    {challenge, method} = generate_pkce()
    pkce_query = %{code_challenge: challenge, code_challenge_method: method}
    oauth_query = SignInWithOauth.options_to_query(oauth)
    query = pkce_query |> Map.merge(oauth_query) |> Map.new(fn {k, v} -> {to_string(k), v} end)

    client
    |> GoTrue.Request.base(@single_user_uri <> @identity_authorize_uri)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_query(query)
    |> Fetcher.request()
    |> case do
      {:ok, response} ->
        {:ok, %{url: response.body["url"], provider: oauth.provider}}

      error ->
        error
    end
  end

  def link_identity(%Client{} = client, access_token, %SignInWithOauth{} = oauth) when is_binary(access_token) do
    oauth_query = SignInWithOauth.options_to_query(oauth)
    query = Map.new(oauth_query, fn {k, v} -> {to_string(k), v} end)

    client
    |> GoTrue.Request.base(@single_user_uri <> @identity_authorize_uri)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_query(query)
    |> Fetcher.request()
    |> case do
      {:ok, response} ->
        {:ok, %{url: response.body["url"], provider: oauth.provider}}

      error ->
        error
    end
  end

  def link_identity(%Client{}, nil, _) do
    {:error, %Supabase.Error{message: "Missing access token", code: :unauthorized}}
  end

  @doc """
  Unlink an identity from the user's account.

  This endpoint requires authentication.
  """
  def unlink_identity(%Client{} = client, access_token, identity_id)
      when is_binary(access_token) and is_binary(identity_id) do
    client
    |> GoTrue.Request.base(@single_user_uri <> @identities_uri <> "/#{identity_id}")
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_method(:delete)
    |> Fetcher.request()
    |> case do
      {:ok, _} -> :ok
      err -> err
    end
  end

  def unlink_identity(%Client{}, nil, _) do
    {:error, %Supabase.Error{message: "Missing access token", code: :unauthorized}}
  end

  @doc """
  Get all identities for the authenticated user.

  This endpoint requires authentication.
  """
  def get_user_identities(%Client{} = client, access_token) when is_binary(access_token) do
    client
    |> GoTrue.Request.base(@single_user_uri <> @identities_uri)
    |> Request.with_headers(%{"authorization" => "Bearer #{access_token}"})
    |> Request.with_method(:get)
    |> Fetcher.request()
  end

  def get_user_identities(%Client{}, nil) do
    {:error, %Supabase.Error{message: "Missing access token", code: :unauthorized}}
  end
end
