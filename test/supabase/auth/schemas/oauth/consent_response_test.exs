defmodule Supabase.Auth.Schemas.OAuth.ConsentResponseTest do
  use ExUnit.Case, async: true

  alias Supabase.Auth.Schemas.OAuth.ConsentResponse

  describe "parse/1" do
    test "successfully parses valid consent response" do
      attrs = %{
        "redirect_url" => "https://example.com/callback?code=abc123"
      }

      assert {:ok, response} = ConsentResponse.parse(attrs)
      assert response.redirect_url == "https://example.com/callback?code=abc123"
    end

    test "returns error when redirect_url is missing" do
      assert {:error, changeset} = ConsentResponse.parse(%{})
      refute changeset.valid?
      assert %{redirect_url: ["can't be blank"]} = errors_on(changeset)
    end

    test "successfully parses with query parameters in URL" do
      attrs = %{
        "redirect_url" => "https://example.com/callback?code=xyz789&state=some-state"
      }

      assert {:ok, response} = ConsentResponse.parse(attrs)
      assert response.redirect_url == "https://example.com/callback?code=xyz789&state=some-state"
    end
  end

  # Helper function to get errors from changeset
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
