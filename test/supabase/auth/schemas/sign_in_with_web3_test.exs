defmodule Supabase.Auth.Schemas.SignInWithWeb3Test do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.SignInWithWeb3

  describe "parse/1" do
    test "parses valid ethereum credentials" do
      attrs = %{chain: :ethereum, message: "Sign in message", signature: "0xabc123"}

      assert {:ok, %SignInWithWeb3{} = result} = SignInWithWeb3.parse(attrs)
      assert result.chain == :ethereum
      assert result.message == "Sign in message"
      assert result.signature == "0xabc123"
      assert result.options == %SignInWithWeb3.Options{}
    end

    test "parses valid solana credentials" do
      attrs = %{chain: :solana, message: "Sign in message", signature: "base58sig"}

      assert {:ok, %SignInWithWeb3{} = result} = SignInWithWeb3.parse(attrs)
      assert result.chain == :solana
    end

    test "parses string keys" do
      attrs = %{"chain" => "ethereum", "message" => "msg", "signature" => "sig"}

      assert {:ok, %SignInWithWeb3{}} = SignInWithWeb3.parse(attrs)
    end

    test "parses with captcha token option" do
      attrs = %{
        chain: :ethereum,
        message: "msg",
        signature: "sig",
        options: %{captcha_token: "token123"}
      }

      assert {:ok, %SignInWithWeb3{} = result} = SignInWithWeb3.parse(attrs)
      assert result.options.captcha_token == "token123"
    end

    test "returns error when chain is missing" do
      attrs = %{message: "msg", signature: "sig"}

      assert {:error, changeset} = SignInWithWeb3.parse(attrs)
      assert errors_on(changeset)[:chain]
    end

    test "returns error when message is missing" do
      attrs = %{chain: :ethereum, signature: "sig"}

      assert {:error, changeset} = SignInWithWeb3.parse(attrs)
      assert errors_on(changeset)[:message]
    end

    test "returns error when signature is missing" do
      attrs = %{chain: :ethereum, message: "msg"}

      assert {:error, changeset} = SignInWithWeb3.parse(attrs)
      assert errors_on(changeset)[:signature]
    end

    test "returns error for unsupported chain" do
      attrs = %{chain: :bitcoin, message: "msg", signature: "sig"}

      assert {:error, changeset} = SignInWithWeb3.parse(attrs)
      assert errors_on(changeset)[:chain]
    end
  end

  describe "to_sign_in_params/1" do
    test "converts to sign in params map" do
      signin = %SignInWithWeb3{
        chain: :ethereum,
        message: "msg",
        signature: "sig",
        options: %SignInWithWeb3.Options{}
      }

      params = SignInWithWeb3.to_sign_in_params(signin)

      assert params == %{chain: "ethereum", message: "msg", signature: "sig"}
    end
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
