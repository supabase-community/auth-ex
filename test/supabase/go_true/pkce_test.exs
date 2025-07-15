defmodule Supabase.Auth.PKCETest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.PKCE

  describe "generate_verifier/0" do
    test "generates a random string of a fixed 56 length" do
      verifier = PKCE.generate_verifier()
      assert String.length(verifier) == 56
    end
  end

  describe "generate_challenge/1" do
    test "generates a challenge from a verifier" do
      verifier = PKCE.generate_verifier()
      challenge = PKCE.generate_challenge(verifier)
      assert challenge != verifier
    end
  end
end
