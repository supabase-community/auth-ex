defmodule Supabase.Auth.PKCE do
  @moduledoc """
  This module is used to generate PKCE (Proof Key for Code Exchange) values.
  """

  @verifier_length 56

  @doc """
  Generate a random string of a fized 56 length to be used as the
  code verifier.

  ## Examples

      iex> Supabase.Auth.PKCE.generate_verifier()
  """
  def generate_verifier do
    @verifier_length
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
    |> String.slice(0, @verifier_length)
  end

  @doc """
  Generate a challenge from a verifier. The challenge is used to
  verify the verifier when exchanging the code.

  ## Examples

      iex> verifier = Supabase.Auth.PKCE.generate_verifier()
      iex> Supabase.Auth.PKCE.generate_challenge(verifier)
  """
  def generate_challenge(verifier) do
    :sha256
    |> :crypto.hash(verifier)
    |> Base.url_encode64(padding: false)
  end
end
