defmodule Supabase.Auth.ErrorFixture do
  @moduledoc """
  This module is used to generate fixtures for the `Supabase.Error` schema.
  """

  alias Supabase.Error

  @doc "Generate a error fixture."
  def error_fixture(attrs \\ %{}) do
    default = %{
      code: :not_found,
      message: "Resource Not Found",
      service: :storage,
      metadata: %{
        path: "/api/resource",
        req_body: %{},
        resp_body: "Not found",
        headers: [{"content-type", "application/json"}]
      }
    }

    attrs
    |> Map.new()
    |> Enum.into(default)
    |> then(&struct(Error, &1))
  end

  def error_fixture_json(attrs \\ %{}) do
    attrs |> error_fixture() |> Supabase.encode_json()
  end
end
