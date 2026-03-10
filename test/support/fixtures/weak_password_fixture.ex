defmodule Supabase.Auth.WeakPasswordFixture do
  @moduledoc """
  Fixtures for weak password error responses from GoTrue.
  """

  def weak_password_resp_body(opts \\ []) do
    reasons = Keyword.get(opts, :reasons, ["length"])
    message = Keyword.get(opts, :message, "Password should be at least 6 characters.")

    %{
      "error_code" => "weak_password",
      "msg" => message,
      "weak_password" => %{"reasons" => reasons}
    }
  end

  def weak_password_error_json(opts \\ []) do
    opts |> weak_password_resp_body() |> Supabase.encode_json()
  end
end
