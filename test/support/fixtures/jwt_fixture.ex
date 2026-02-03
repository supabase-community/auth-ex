defmodule Supabase.Auth.JWTFixture do
  @moduledoc """
  This module provides JWT fixtures for testing.
  """

  @doc """
  Generates a valid JWT with HS256 algorithm.
  """
  def hs256_jwt(claims \\ %{}) do
    default_claims = %{
      "sub" => "user-123",
      "email" => "test@example.com",
      "role" => "authenticated",
      "iat" => System.os_time(:second),
      "exp" => System.os_time(:second) + 3600
    }

    jwk = JOSE.JWK.from(%{"kty" => "oct", "k" => Base.url_encode64("test-secret", padding: false)})
    jwt_claims = Map.merge(default_claims, claims)

    jwt = JOSE.JWT.from(jwt_claims)

    {_jws, token} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => "HS256"}, jwt)
      |> JOSE.JWS.compact()

    token
  end

  @doc """
  Generates a valid JWT with RS256 algorithm and kid.
  """
  def rs256_jwt(claims \\ %{}, kid \\ "test-key-id") do
    default_claims = %{
      "sub" => "user-456",
      "email" => "rsa@example.com",
      "role" => "authenticated",
      "iat" => System.os_time(:second),
      "exp" => System.os_time(:second) + 3600
    }

    # Generate RSA key pair
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    jwt_claims = Map.merge(default_claims, claims)
    jwt = JOSE.JWT.from(jwt_claims)

    {_jws, token} =
      jwk
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => kid}, jwt)
      |> JOSE.JWS.compact()

    {token, jwk}
  end

  @doc """
  Generates an expired JWT.
  """
  def expired_jwt do
    claims = %{
      "sub" => "user-expired",
      "email" => "expired@example.com",
      "exp" => System.os_time(:second) - 3600
    }

    hs256_jwt(claims)
  end

  @doc """
  Generates JWKS from a JWK.
  """
  def jwks_from_jwk(jwk, kid \\ "test-key-id") do
    jwk_map =
      jwk
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> Map.put("kid", kid)

    %{"keys" => [jwk_map]}
  end

  @doc """
  Returns an invalid JWT string.
  """
  def invalid_jwt do
    "invalid.jwt.token"
  end
end
